package spoof

import (
	"bytes"
	"crypto/rand"
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
