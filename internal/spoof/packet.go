package spoof

import (
	"crypto/sha256"
	"encoding/binary"
	mrand "math/rand/v2"
	"net/netip"
	"strings"
)

// iranPrefixes are major Iranian public IPv4 blocks used when SpoofSrc == "iran".
var iranPrefixes = [][3]byte{
	{2, 176, 0},
	{5, 160, 0},
	{5, 200, 0},
	{31, 56, 0},
	{37, 156, 0},
	{46, 209, 0},
	{78, 39, 0},
	{80, 191, 0},
	{85, 185, 0},
	{91, 98, 0},
	{94, 182, 0},
	{151, 232, 0},
	{178, 131, 0},
	{185, 143, 232},
	{188, 158, 0},
	{217, 218, 0},
}

// globalPublicOctets are safe non-bogon public first octets for "auto" / "rotate".
var globalPublicOctets = []byte{
	45, 51, 62, 77, 81, 84, 88, 89, 91, 93, 95, 109, 138, 141, 145, 149, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217,
}

// resolveSpoofSrc returns the outer source IPv4 address for this packet.
// When this side does not spoof (per Dir), it returns c.Local.
func resolveSpoofSrc(c Config, seq uint64) [4]byte {
	if !ShouldSpoof(c.Dir, c.Side) && c.Local.Is4() {
		return c.Local.As4()
	}
	spec := strings.TrimSpace(c.SpoofSrc)
	if strings.Contains(spec, ",") {
		parts := strings.Split(spec, ",")
		if c.Side >= 0 && c.Side < len(parts) {
			spec = strings.TrimSpace(parts[c.Side])
		} else {
			spec = strings.TrimSpace(parts[0])
		}
	}
	switch strings.ToLower(spec) {
	case "", SrcAuto:
		h := sha256.Sum256([]byte(c.Secret + "|spoof-src|" + c.Tunnel + "|" + string(rune('0'+c.Side))))
		first := globalPublicOctets[int(h[0])%len(globalPublicOctets)]
		host := h[3]
		if host == 0 || host == 255 {
			host = 42
		}
		return [4]byte{first, h[1], h[2], host}
	case SrcIran:
		// Rotate every 256 packets across Iranian public blocks.
		idx := int((seq>>8)+uint64(c.Side*7)) % len(iranPrefixes)
		p := iranPrefixes[idx]
		b2 := p[2]
		if b2 == 0 {
			b2 = byte(((seq >> 4) ^ uint64(c.Port)) & 0xfe)
		}
		b3 := byte((seq ^ uint64(c.Side*31+17)) & 0xff)
		if b3 == 0 || b3 == 255 {
			b3 = 73
		}
		return [4]byte{p[0], p[1], b2, b3}
	case SrcRotate:
		x := seq*0x9e3779b97f4a7c15 + uint64(c.Side)*0x517cc1b727220a95
		first := globalPublicOctets[int(x>>56)%len(globalPublicOctets)]
		b1 := byte((x >> 16) & 0xff)
		b2 := byte((x >> 8) & 0xff)
		b3 := byte(x & 0xff)
		if b3 == 0 || b3 == 255 {
			b3 = 19
		}
		return [4]byte{first, b1, b2, b3}
	default:
		if a, err := netip.ParseAddr(spec); err == nil && a.Is4() {
			return a.As4()
		}
		if c.Local.Is4() {
			return c.Local.As4()
		}
		return [4]byte{185, 143, 233, 17}
	}
}

// ipv4Checksum calculates the standard RFC 1071 16-bit one's complement checksum.
func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if n&1 != 0 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// l4Checksum calculates a TCP or UDP checksum over the IPv4 pseudo-header and
// the L4 segment (header + payload).
func l4Checksum(src, dst [4]byte, proto uint8, seg []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(proto)
	sum += uint32(len(seg))

	n := len(seg)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(seg[i : i+2]))
	}
	if n&1 != 0 {
		sum += uint32(seg[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	if cs == 0 && proto == 17 {
		return 0xffff
	}
	return cs
}

// buildOuterPacket writes the full raw IPv4 packet (20-byte IPv4 header +
// outer protocol header + payload) into out and returns the slice.
func buildOuterPacket(out []byte, c Config, proto string, src, dst [4]byte, payload []byte, seq uint64) []byte {
	hl := ProtoHeaderLen(proto)
	totalLen := 20 + hl + len(payload)
	if len(out) < totalLen {
		out = make([]byte, totalLen)
	}
	// Copy payload into place first (safe even if payload aliases out).
	copy(out[20+hl:totalLen], payload)

	ipProto := uint8(IPProto(proto))
	ttl := c.TTL
	if ttl == 0 {
		ttl = 64
	}
	df := uint16(0x4000)
	if c.NoDF {
		df = 0
	}
	id := uint16(seq & 0xffff)
	if id == 0 {
		id = uint16(mrand.Uint32())
	}

	// 20-byte IPv4 header
	out[0] = 0x45
	out[1] = c.DSCP << 2
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(out[4:6], id)
	binary.BigEndian.PutUint16(out[6:8], df)
	out[8] = ttl
	out[9] = ipProto
	out[10], out[11] = 0, 0
	copy(out[12:16], src[:])
	copy(out[16:20], dst[:])
	binary.BigEndian.PutUint16(out[10:12], ipv4Checksum(out[:20]))

	dport := c.Port
	if dport == 0 {
		dport = 32443
	}
	sport := dport ^ uint16(0x2531+c.Side*19)
	if sport < 1024 {
		sport += 10000
	}

	l4 := out[20:totalLen]
	switch NormalizeProto(proto) {
	case ProtoUDP:
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
		l4[6], l4[7] = 0, 0
		binary.BigEndian.PutUint16(l4[6:8], l4Checksum(src, dst, ipProto, l4))
	case ProtoTCP:
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint32(l4[4:8], uint32(seq*1360+0x10203040))
		binary.BigEndian.PutUint32(l4[8:12], uint32(seq*512+0x50607080))
		l4[12] = 5 << 4 // 20-byte TCP header
		l4[13] = 0x18   // PSH | ACK
		binary.BigEndian.PutUint16(l4[14:16], 65535)
		l4[16], l4[17] = 0, 0
		l4[18], l4[19] = 0, 0
		binary.BigEndian.PutUint16(l4[16:18], l4Checksum(src, dst, ipProto, l4))
	case ProtoGRE:
		// GRE with Key Present (0x2000), protocol 0x6558 (Transparent Ethernet / custom) or 0x0800
		binary.BigEndian.PutUint16(l4[0:2], 0x2000)
		binary.BigEndian.PutUint16(l4[2:4], 0x0800)
		key := c.Key
		if key == 0 {
			key = uint32(dport)<<16 | 0x4d4b
		}
		binary.BigEndian.PutUint32(l4[4:8], key)
	case ProtoICMP:
		// ICMP Echo Reply (Type 0, Code 0) so the receiving kernel never sends an automatic Echo Reply
		l4[0] = 0
		l4[1] = 0
		l4[2], l4[3] = 0, 0
		binary.BigEndian.PutUint16(l4[4:6], dport)
		binary.BigEndian.PutUint16(l4[6:8], uint16(seq&0xffff))
		binary.BigEndian.PutUint16(l4[2:4], ipv4Checksum(l4))
	case ProtoIPIP, ProtoSIT:
		// 0-byte transport header; payload follows the 20-byte IPv4 header directly.
	}
	return out[:totalLen]
}

// extractRawPayload strips the outer IPv4 header (if delivered by the raw
// socket) and the outer protocol header, returning the inner spoof frame.
func extractRawPayload(raw []byte, proto string, wantPort uint16, wantKey uint32) ([]byte, bool) {
	p := raw
	if len(p) >= 20 && p[0]>>4 == 4 {
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || ihl > len(p) {
			return nil, false
		}
		tot := int(binary.BigEndian.Uint16(p[2:4]))
		if tot >= ihl && tot <= len(p) {
			p = p[:tot]
		}
		p = p[ihl:]
	}
	switch NormalizeProto(proto) {
	case ProtoUDP:
		if len(p) < 8 {
			return nil, false
		}
		dport := binary.BigEndian.Uint16(p[2:4])
		if wantPort != 0 && dport != wantPort {
			return nil, false
		}
		return p[8:], true
	case ProtoTCP:
		if len(p) < 20 {
			return nil, false
		}
		dport := binary.BigEndian.Uint16(p[2:4])
		if wantPort != 0 && dport != wantPort {
			return nil, false
		}
		doff := int(p[12]>>4) * 4
		if doff < 20 || doff > len(p) {
			return nil, false
		}
		return p[doff:], true
	case ProtoGRE:
		if len(p) < 4 {
			return nil, false
		}
		flags := binary.BigEndian.Uint16(p[0:2])
		off := 4
		if flags&0x8000 != 0 { // Checksum present
			off += 4
		}
		if flags&0x2000 != 0 { // Key present
			if len(p) < off+4 {
				return nil, false
			}
			key := binary.BigEndian.Uint32(p[off : off+4])
			if wantKey != 0 && key != wantKey {
				return nil, false
			}
			off += 4
		}
		if flags&0x1000 != 0 { // Sequence present
			off += 4
		}
		if off > len(p) {
			return nil, false
		}
		return p[off:], true
	case ProtoICMP:
		if len(p) < 8 {
			return nil, false
		}
		// Accept Echo Reply (0) or Echo Request (8) matching wantPort (if set)
		if p[0] != 0 && p[0] != 8 {
			return nil, false
		}
		id := binary.BigEndian.Uint16(p[4:6])
		if wantPort != 0 && id != wantPort {
			return nil, false
		}
		return p[8:], true
	case ProtoIPIP, ProtoSIT:
		return p, len(p) > 0
	default:
		return p, len(p) > 0
	}
}
