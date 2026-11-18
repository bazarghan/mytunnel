// Package spoof implements NeoTunnel's forged-source-IP (IP spoofing) carrier
// and user-space tunnel.
//
// A Spoof tunnel encapsulates IPv4 and IPv6 packets from a TUN interface (or
// from any upper-layer tunnel stacked over it: 6to4, GRE, IPIP, WireGuard,
// VXLAN, GENEVE, L2TPv3, EoIP, TCP, TCP+mux, TLS+mux) into raw IPv4 packets
// whose outer source IP address is forged (spoofed). Because the receiving
// server cannot identify packets by their outer source IP, every frame is
// cryptographically authenticated (and optionally encrypted with AES-128-GCM
// or XChaCha20-Poly1305) using keys derived from the tunnel's shared secret.
//
// Supported outer carrier protocols (Proto):
//   - "udp"  (IP proto 17): UDP datagrams with a spoofed source IP
//   - "tcp"  (IP proto 6):  FakeTCP / raw TCP PSH-ACK segments with a spoofed source IP
//   - "gre"  (IP proto 47): GRE frames with a spoofed source IP
//   - "ipip" (IP proto 4):  IPIP packets with a spoofed source IP
//   - "sit"  (IP proto 41): SIT / 6to4 packets with a spoofed source IP
//   - "icmp" (IP proto 1):  ICMP Echo Reply frames with a spoofed source IP
package spoof

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Outer wire protocols carried by a Spoof tunnel.
const (
	ProtoUDP  = "udp"
	ProtoTCP  = "tcp"
	ProtoGRE  = "gre"
	ProtoIPIP = "ipip"
	ProtoSIT  = "sit"
	ProtoICMP = "icmp"
)

// Spoof directions (which side forges its outer source IP).
const (
	DirBoth = "both" // both side 0 and side 1 forge their outer source IP (default)
	DirOut  = "out"  // side 0 (main server) forges source IP; side 1 uses real IP
	DirIn   = "in"   // side 1 (destination server) forges source IP; side 0 uses real IP
)

// Spoof source IP modes.
const (
	SrcAuto   = "auto"   // deterministic realistic public IPv4 per tunnel side
	SrcIran   = "iran"   // realistic Iranian public IPv4 from Iran CIDR blocks
	SrcRotate = "rotate" // rotate spoofed public IPv4 dynamically across packets
)

// Protos lists all supported outer wire protocols in order.
func Protos() []string {
	return []string{ProtoUDP, ProtoTCP, ProtoGRE, ProtoIPIP, ProtoSIT, ProtoICMP}
}

// NormalizeProto returns a canonical outer protocol name ("udp" when empty).
func NormalizeProto(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "udp":
		return ProtoUDP
	case "tcp", "faketcp", "rawtcp":
		return ProtoTCP
	case "gre":
		return ProtoGRE
	case "ipip", "ip4":
		return ProtoIPIP
	case "sit", "6to4", "ipv6":
		return ProtoSIT
	case "icmp", "ping":
		return ProtoICMP
	default:
		return strings.ToLower(strings.TrimSpace(p))
	}
}

// ValidProto reports whether p is a supported outer spoof protocol.
func ValidProto(p string) bool {
	switch NormalizeProto(p) {
	case ProtoUDP, ProtoTCP, ProtoGRE, ProtoIPIP, ProtoSIT, ProtoICMP:
		return true
	}
	return false
}

// IPProto returns the IPv4 protocol number for the outer spoof header.
func IPProto(p string) int {
	switch NormalizeProto(p) {
	case ProtoTCP:
		return unix.IPPROTO_TCP // 6
	case ProtoGRE:
		return unix.IPPROTO_GRE // 47
	case ProtoIPIP:
		return unix.IPPROTO_IPIP // 4
	case ProtoSIT:
		return unix.IPPROTO_IPV6 // 41
	case ProtoICMP:
		return unix.IPPROTO_ICMP // 1
	default:
		return unix.IPPROTO_UDP // 17
	}
}

// ProtoHeaderLen returns the outer transport header size (after the 20-byte
// IPv4 header) for protocol p.
func ProtoHeaderLen(p string) int {
	switch NormalizeProto(p) {
	case ProtoTCP:
		return 20
	case ProtoUDP, ProtoGRE, ProtoICMP:
		return 8
	case ProtoIPIP, ProtoSIT:
		return 0
	default:
		return 8
	}
}

// OverheadFor returns the total wire overhead in bytes for a Spoof tunnel
// given its outer protocol and whether full AEAD encryption is active.
func OverheadFor(proto string, noCrypt bool) int {
	ip := 20 + ProtoHeaderLen(proto)
	if noCrypt {
		return ip + AuthOverhead
	}
	return ip + CryptOverhead
}

// NormalizeDir returns a canonical spoof direction ("both" when empty).
func NormalizeDir(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "", "both", "all", "2":
		return DirBoth
	case "out", "local", "side0", "0", "iran":
		return DirOut
	case "in", "remote", "side1", "1", "foreign":
		return DirIn
	default:
		return strings.ToLower(strings.TrimSpace(d))
	}
}

// ValidDir reports whether d is a valid spoof direction.
func ValidDir(d string) bool {
	switch NormalizeDir(d) {
	case DirBoth, DirOut, DirIn:
		return true
	}
	return false
}

// ShouldSpoof reports whether side (0 or 1) should forge its outer source IP
// under direction dir.
func ShouldSpoof(dir string, side int) bool {
	switch NormalizeDir(dir) {
	case DirOut:
		return side == 0
	case DirIn:
		return side == 1
	default:
		return true
	}
}

// ValidateSrc checks a spoof source IP specification: "", "auto", "iran",
// "rotate", a single IPv4 address "1.2.3.4", or a pair "1.2.3.4,5.6.7.8" for
// side 0 and side 1.
func ValidateSrc(src string) error {
	s := strings.ToLower(strings.TrimSpace(src))
	switch s {
	case "", SrcAuto, SrcIran, SrcRotate:
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == SrcAuto || part == SrcIran || part == SrcRotate {
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil || !a.Is4() {
			return fmt.Errorf("spoof source %q must be auto, iran, rotate, or an IPv4 address", part)
		}
		if a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() {
			return fmt.Errorf("spoof source %s cannot be loopback, multicast or 0.0.0.0", a)
		}
	}
	return nil
}

// Config describes this node's end of a running Spoof tunnel.
type Config struct {
	Name      string // TUN interface name (e.g. "nt-t1" or "nt-t1-s")
	Tunnel    string // tunnel key name shared by both ends
	Secret    string // base64 shared secret
	Side      int    // 0 or 1
	Local     netip.Addr
	Remote    netip.Addr
	Port      uint16
	Key       uint32
	Proto     string // "udp", "tcp", "gre", "ipip", "sit", "icmp"
	Dir       string // "both", "out", "in"
	SpoofSrc  string // "", "auto", "iran", "rotate", or custom IPv4(s)
	TTL       uint8
	DSCP      uint8
	NoDF      bool
	Padding   int
	Keepalive time.Duration
	AES       bool // use AES-128-GCM when both ends support it
	NoCrypt   bool // authenticate only (used when an encrypted tunnel is stacked on top)
}
