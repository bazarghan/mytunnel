package spoof

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestCodecAndPacketsAllProtos(t *testing.T) {
	var sendKey, recvKey [32]byte
	rand.Read(sendKey[:])
	recvKey = sendKey

	for _, noCrypt := range []bool{false, true} {
		for _, useAES := range []bool{false, true} {
			if noCrypt && useAES {
				continue
			}
			cdSend, err := newCodec(sendKey[:], recvKey[:], 16, noCrypt)
			if err != nil {
				t.Fatal(err)
			}
			cdRecv, err := newCodec(recvKey[:], sendKey[:], 16, noCrypt)
			if err != nil {
				t.Fatal(err)
			}
			if useAES {
				if err := cdSend.useAES(sendKey[:], recvKey[:]); err != nil {
					t.Fatal(err)
				}
				if err := cdRecv.useAES(recvKey[:], sendKey[:]); err != nil {
					t.Fatal(err)
				}
			}

			for _, proto := range Protos() {
				cfg := Config{
					Name:     "nt-sp1",
					Tunnel:   "sp1",
					Secret:   "dGVzdHNlY3JldDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
					Side:     0,
					Local:    netip.MustParseAddr("198.51.100.10"),
					Remote:   netip.MustParseAddr("203.0.113.20"),
					Port:     32443,
					Key:      0x12345678,
					Proto:    proto,
					Dir:      DirBoth,
					SpoofSrc: SrcIran,
					NoCrypt:  noCrypt,
				}
				inner := []byte("hello over spoof tunnel on proto " + proto)
				buf := make([]byte, cdSend.room(len(inner)))
				frame := cdSend.seal(buf, typeData, inner, uint32(time.Now().Unix()))

				src := resolveSpoofSrc(cfg, 1)
				if src == cfg.Local.As4() {
					t.Fatalf("expected forged source IP for proto %s, got local IP", proto)
				}
				dst := cfg.Remote.As4()
				raw := buildOuterPacket(nil, cfg, proto, src, dst, frame, 1)

				extracted, ok := extractRawPayload(raw, proto, cfg.Port, cfg.Key)
				if !ok {
					t.Fatalf("extractRawPayload failed for proto %s", proto)
				}
				// Make a copy since open decrypts in place
				frameCopy := append([]byte(nil), extracted...)
				typ, got, err := cdRecv.open(frameCopy)
				if err != nil {
					t.Fatalf("open failed for proto %s (noCrypt=%v, aes=%v): %v", proto, noCrypt, useAES, err)
				}
				if typ != typeData || !bytes.Equal(got, inner) {
					t.Fatalf("mismatch for proto %s: got %q, want %q", proto, got, inner)
				}
			}
		}
	}
}

func TestPortForSideAndPinholeSymmetry(t *testing.T) {
	if got := effectivePort(0); got != 32443 {
		t.Fatalf("effectivePort(0) = %d, want 32443", got)
	}
	// Wraparound: dport ^ (0x2531 + side*19) == 0 -> +10000
	if got := portForSide(0x2531, 0); got != 10000 {
		t.Fatalf("portForSide(0x2531, 0) = %d, want 10000", got)
	}
	if got := portForSide(0x2531+19, 1); got != 10000 {
		t.Fatalf("portForSide(0x2544, 1) = %d, want 10000", got)
	}

	for _, proto := range []string{ProtoUDP, ProtoTCP} {
		for _, port := range []uint16{0, 40000, 0x2531 + 19} {
			cfg0 := Config{
				Tunnel:   "sp-sym",
				Secret:   "dGVzdHNlY3JldDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
				Side:     0,
				Local:    netip.MustParseAddr("198.51.100.10"),
				Remote:   netip.MustParseAddr("203.0.113.20"),
				Port:     port,
				Proto:    proto,
				Dir:      DirBoth,
				SpoofSrc: "185.143.232.200,8.8.8.8",
			}
			cfg1 := cfg0
			cfg1.Side = 1
			cfg1.Local, cfg1.Remote = cfg0.Remote, cfg0.Local

			// Peer (side 1) sends outer packet to side 0.
			peerSrc := resolveSpoofSrc(cfg1, 7)
			outer := buildOuterPacket(nil, cfg1, proto, peerSrc, cfg1.Remote.As4(), []byte("ping"), 7)

			// Side 0 predicts peer's outer source IP and emits pinhole packet.
			expectedPeerSrc, ok := peerExpectedOuterSrc(cfg0)
			if !ok || expectedPeerSrc.As4() != peerSrc {
				t.Fatalf("proto=%s port=%d: peerExpectedOuterSrc = (%v, %v), want %v", proto, port, expectedPeerSrc, ok, netip.AddrFrom4(peerSrc))
			}
			pinhole := buildPinholePacket(nil, cfg0, proto, expectedPeerSrc.As4(), 7)

			// Verify reversed 5-tuple symmetry.
			if !bytes.Equal(pinhole[12:16], outer[16:20]) {
				t.Fatalf("proto=%s port=%d: pinhole SrcIP %v != outer DstIP %v", proto, port, pinhole[12:16], outer[16:20])
			}
			if !bytes.Equal(pinhole[16:20], outer[12:16]) {
				t.Fatalf("proto=%s port=%d: pinhole DstIP %v != outer SrcIP %v", proto, port, pinhole[16:20], outer[12:16])
			}
			pinSport := binary.BigEndian.Uint16(pinhole[20:22])
			pinDport := binary.BigEndian.Uint16(pinhole[22:24])
			outSport := binary.BigEndian.Uint16(outer[20:22])
			outDport := binary.BigEndian.Uint16(outer[22:24])
			if pinSport != outDport || pinDport != outSport {
				t.Fatalf("proto=%s port=%d: ports mismatch: pinhole=(%d->%d), outer=(%d->%d)", proto, port, pinSport, pinDport, outSport, outDport)
			}
		}
	}
}

func TestBuildPinholePacketAllProtos(t *testing.T) {
	wantLens := map[string]int{
		ProtoUDP:  29,
		ProtoTCP:  40,
		ProtoGRE:  28,
		ProtoIPIP: 20,
		ProtoSIT:  20,
		ProtoICMP: 28,
	}

	for _, proto := range Protos() {
		cfg := Config{
			Tunnel:   "sp-pin",
			Secret:   "dGVzdHNlY3JldDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
			Side:     0,
			Local:    netip.MustParseAddr("198.51.100.10"),
			Remote:   netip.MustParseAddr("203.0.113.20"),
			Port:     32443,
			Key:      0x12345678,
			Proto:    proto,
			Dir:      DirBoth,
			SpoofSrc: "185.143.232.200,8.8.8.8",
		}
		dstAddr, ok := peerExpectedOuterSrc(cfg)
		if !ok {
			t.Fatalf("proto %s: expected predictable peer outer src", proto)
		}
		dst := dstAddr.As4()

		// Reuse a dirty buffer filled with 0xff to ensure zero stale bytes leak.
		dirty := bytes.Repeat([]byte{0xff}, 64)
		pkt := buildPinholePacket(dirty, cfg, proto, dst, 42)

		if len(pkt) != wantLens[proto] {
			t.Fatalf("proto %s: len = %d, want %d", proto, len(pkt), wantLens[proto])
		}
		if pkt[0] != 0x45 {
			t.Fatalf("proto %s: IPv4 version/IHL = %#x, want 0x45", proto, pkt[0])
		}
		if tot := int(binary.BigEndian.Uint16(pkt[2:4])); tot != len(pkt) {
			t.Fatalf("proto %s: IPv4 totlen = %d, want %d", proto, tot, len(pkt))
		}
		if int(pkt[9]) != IPProto(proto) {
			t.Fatalf("proto %s: IPv4 proto = %d, want %d", proto, pkt[9], IPProto(proto))
		}
		src := cfg.Local.As4()
		if !bytes.Equal(pkt[12:16], src[:]) {
			t.Fatalf("proto %s: pinhole SrcIP = %v, must be real local IP %v", proto, pkt[12:16], cfg.Local)
		}
		if !bytes.Equal(pkt[16:20], dst[:]) {
			t.Fatalf("proto %s: pinhole DstIP = %v, want %v", proto, pkt[16:20], dst)
		}
		if cs := ipv4Checksum(pkt[:20]); cs != 0 {
			t.Fatalf("proto %s: invalid IPv4 checksum residue = %#04x", proto, cs)
		}

		l4 := pkt[20:]
		switch proto {
		case ProtoUDP:
			if gotLen := binary.BigEndian.Uint16(l4[4:6]); gotLen != 9 {
				t.Fatalf("udp length = %d, want 9", gotLen)
			}
			if l4[8] != 0x00 {
				t.Fatalf("udp dummy payload byte = %#02x, want 0x00", l4[8])
			}
			if res := l4Checksum(src, dst, 17, l4); res != 0xffff {
				t.Fatalf("udp checksum verification failed: residue = %#04x", res)
			}
		case ProtoTCP:
			if ack := binary.BigEndian.Uint32(l4[8:12]); ack != 0 {
				t.Fatalf("tcp ack = %d, want 0", ack)
			}
			if l4[12] != 5<<4 || l4[13] != 0x02 {
				t.Fatalf("tcp hdrlen/flags = (%#02x, %#02x), want (0x50, 0x02)", l4[12], l4[13])
			}
			if res := l4Checksum(src, dst, 6, l4); res != 0 {
				t.Fatalf("tcp checksum verification failed: residue = %#04x", res)
			}
		case ProtoGRE:
			if flags := binary.BigEndian.Uint16(l4[0:2]); flags != 0x2000 {
				t.Fatalf("gre flags = %#04x, want 0x2000", flags)
			}
			if key := binary.BigEndian.Uint32(l4[4:8]); key != cfg.Key {
				t.Fatalf("gre key = %#08x, want %#08x", key, cfg.Key)
			}
		case ProtoICMP:
			if l4[0] != 8 || l4[1] != 0 {
				t.Fatalf("icmp type/code = (%d, %d), want (8, 0)", l4[0], l4[1])
			}
			if id := binary.BigEndian.Uint16(l4[4:6]); id != cfg.Port {
				t.Fatalf("icmp id = %d, want %d", id, cfg.Port)
			}
			if res := ipv4Checksum(l4); res != 0 {
				t.Fatalf("icmp checksum verification failed: residue = %#04x", res)
			}
		}
	}
}

func TestPeerExpectedOuterSrcAndValidatePinhole(t *testing.T) {
	base := Config{
		Tunnel: "sp-peer",
		Secret: "dGVzdHNlY3JldDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		Side:   0,
		Local:  netip.MustParseAddr("198.51.100.10"),
		Remote: netip.MustParseAddr("203.0.113.20"),
		Port:   32443,
	}
	side1Auto := base
	side1Auto.Side = 1
	side1Auto.Local, side1Auto.Remote = base.Remote, base.Local
	side1Auto.Dir = DirBoth
	side1Auto.SpoofSrc = SrcAuto
	wantAuto := netip.AddrFrom4(resolveSpoofSrc(side1Auto, 1))

	cases := []struct {
		name     string
		side     int
		dir      string
		spoofSrc string
		wantOK   bool
		wantIP   netip.Addr
		wantErr  bool
	}{
		{"dir_out_iran", 0, DirOut, SrcIran, true, base.Remote, false},
		{"dir_out_rotate", 0, DirOut, SrcRotate, true, base.Remote, false},
		{"dir_in_iran", 0, DirIn, SrcIran, false, netip.Addr{}, true},
		{"dir_in_auto", 0, DirIn, SrcAuto, true, wantAuto, false},
		{"dir_both_empty", 0, DirBoth, "", true, wantAuto, false},
		{"dir_both_auto", 0, DirBoth, SrcAuto, true, wantAuto, false},
		{"dir_both_single_ip", 0, DirBoth, "185.143.232.200", true, netip.MustParseAddr("185.143.232.200"), false},
		{"dir_both_pair_side0", 0, DirBoth, "185.143.232.200,8.8.8.8", true, netip.MustParseAddr("8.8.8.8"), false},
		{"dir_both_pair_side1", 1, DirBoth, "185.143.232.200,8.8.8.8", true, netip.MustParseAddr("185.143.232.200"), false},
		{"dir_both_iran_pair", 0, DirBoth, "iran,8.8.8.8", true, netip.MustParseAddr("8.8.8.8"), false},
		{"dir_both_iran_auto_pair", 0, DirBoth, "iran,auto", true, wantAuto, false},
		{"dir_both_iran", 0, DirBoth, SrcIran, false, netip.Addr{}, true},
		{"dir_both_rotate", 0, DirBoth, SrcRotate, false, netip.Addr{}, true},
		{"dir_both_pair_remote_iran", 0, DirBoth, "8.8.8.8,iran", false, netip.Addr{}, true},
		{"dir_both_pair_remote_rotate", 0, DirBoth, "auto,rotate", false, netip.Addr{}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.Side = tc.side
			if tc.side == 1 {
				c.Local, c.Remote = base.Remote, base.Local
			}
			c.Dir = tc.dir
			c.SpoofSrc = tc.spoofSrc

			gotIP, gotOK := peerExpectedOuterSrc(c)
			if gotOK != tc.wantOK || gotIP != tc.wantIP {
				t.Fatalf("peerExpectedOuterSrc() = (%v, %v), want (%v, %v)", gotIP, gotOK, tc.wantIP, tc.wantOK)
			}
			err := ValidatePinhole(tc.dir, tc.spoofSrc, tc.side)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidatePinhole() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
