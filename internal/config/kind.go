package config

import "fmt"

type Kind string

const (
	KindSIT       Kind = "sit"       // IPv6 over IPv4 (the "6to4" carrier)
	KindIPIP      Kind = "ipip"      // IPv4 over IPv4
	KindGRE       Kind = "gre"       // L3 GRE over IPv4
	KindGRETAP    Kind = "gretap"    // L2 GRE over IPv4
	KindIP6GRE    Kind = "ip6gre"    // L3 GRE over IPv6
	KindIP6GRETAP Kind = "ip6gretap" // L2 GRE over IPv6
	KindIPIP6     Kind = "ipip6"     // IPv4 over IPv6
	KindIP6IP6    Kind = "ip6ip6"    // IPv6 over IPv6
	KindVXLAN     Kind = "vxlan"     // L2 over UDP
	KindGENEVE    Kind = "geneve"    // L2 over UDP
	KindL2TPv3    Kind = "l2tpv3"    // L2 pseudowire over IP (proto 115) or UDP
	KindWireGuard Kind = "wireguard" // L3, encrypted, over UDP (kernel)
	KindObfs      Kind = "obfs"      // L3, encrypted and obfuscated UDP (user space)
	KindSpoof     Kind = "spoof"     // L3, forged-source-IP carrier over UDP/TCP/GRE/IPIP/SIT/ICMP (user space)
	KindTCP       Kind = "tcp"       // L3 over a TCP connection (user space), optionally encrypted
	KindEoIP      Kind = "eoip"      // L2, MikroTik EoIP / EoIPv6 (user space)
	// Connection tunnels carry each user connection on its own stream over
	// a few long-lived sessions (see internal/transport), not packets.
	KindStreamTCP Kind = "stream-tcp" // sessions over plain TCP, multiplexed
	KindStreamTLS Kind = "stream-tls" // the same inside TLS with a browser's fingerprint
)

// KindInfo describes what a tunnel kind carries and costs.
type KindInfo struct {
	Kind     Kind
	Title    string
	Layer    int  // 2 or 3
	Under6   bool // needs an IPv6 underlay (false = IPv4, or either when UnderAny)
	UnderAny bool // works over IPv4 or IPv6
	Carry4   bool
	Carry6   bool
	// Overhead in bytes for an IPv4 underlay without a port; see OverheadFor.
	Overhead int
	// IPProto is the outer IP protocol (0 for kinds that always use UDP).
	IPProto int
	// FOU: the kind can be wrapped in UDP on a chosen port, which also gets
	// it past protocol filtering.
	FOU bool
	// UDP kinds always run on a port; PortEncap kinds switch to their own
	// UDP encapsulation when a port is set (L2TPv3).
	UDP       bool
	PortEncap bool
	// TCP kinds always run on a TCP port.
	TCP bool
	// Encrypted kinds protect their traffic themselves.
	Encrypted bool
	// Userspace kinds are served by the daemon's own data plane.
	Userspace bool
	// Managed kinds need HLTunnel on both ends (keys are derived from the
	// tunnel's shared secret).
	NeedsPeer bool
	// Stream kinds are connection tunnels: no interface and no inner
	// addresses; their forwards are relays over the tunnel's sessions.
	Stream bool
	// PMTU reports whether the kind honors a tunnel's path MTU discovery flag
	// (kinds that set a DF bit on outer IPv4 packets).
	PMTU bool
	// IgnoreDF reports whether the kind can ignore the inner DF bit.
	IgnoreDF bool
	// Lanes reports whether the kind supports multi-lane spreading (GRE family).
	Lanes bool
	// DefaultPort is the fallback port when no port is configured.
	DefaultPort uint16
	// AutoPort reports whether creating a tunnel automatically picks a free port.
	AutoPort bool
	// HasVNI reports whether the kind carries a 24-bit VNI identifier.
	HasVNI bool
	// HasPadding reports whether packets support random per-packet padding.
	HasPadding bool
	// HasObfsAES reports whether the userspace cipher can upgrade to AES-GCM.
	HasObfsAES bool
	// Modules lists kernel modules required for this kind before link creation.
	Modules []string
	// IPv6Kind is the IPv6-underlay counterpart for IPv4-only underlay kinds.
	IPv6Kind Kind
	// CarrierSuffix is appended to stacked carrier tunnel names (e.g. "-o", "-s").
	CarrierSuffix string
	// ConflictGroup identifies keyless kernel tunnels sharing an endpoint pair.
	ConflictGroup string
	// Hint is the short terminal UI hint shown when selecting a tunnel kind.
	Hint string
}

var kinds = []KindInfo{
	{Kind: KindSIT, Title: "SIT / 6to4 (IPv6 in IPv4)", Layer: 3, Carry6: true, Overhead: 20, IPProto: 41, FOU: true, PMTU: true, IPv6Kind: KindIP6IP6, CarrierSuffix: "-6", ConflictGroup: "sit", Modules: []string{"sit"}, Hint: "IPv6 only, over IPv4"},
	{Kind: KindIPIP, Title: "IPIP (IPv4 in IPv4)", Layer: 3, Carry4: true, Overhead: 20, IPProto: 4, FOU: true, PMTU: true, IPv6Kind: KindIPIP6, ConflictGroup: "ipip", Modules: []string{"ipip"}, Hint: "plain IPv4 in IPv4, the lowest overhead"},
	{Kind: KindGRE, Title: "GRE", Layer: 3, Carry4: true, Carry6: true, Overhead: 24, IPProto: 47, FOU: true, PMTU: true, IgnoreDF: true, Lanes: true, IPv6Kind: KindIP6GRE, Modules: []string{"ip_gre"}, Hint: "standard GRE, works with MikroTik and most routers"},
	{Kind: KindGRETAP, Title: "GRETAP (Ethernet over GRE)", Layer: 2, Carry4: true, Carry6: true, Overhead: 38, IPProto: 47, FOU: true, PMTU: true, IgnoreDF: true, Lanes: true, IPv6Kind: KindIP6GRETAP, Modules: []string{"ip_gre"}, Hint: "layer 2 (Ethernet) over GRE"},
	{Kind: KindIP6GRE, Title: "GRE over IPv6", Layer: 3, Under6: true, Carry4: true, Carry6: true, Overhead: 44, IPProto: 47, Lanes: true, Modules: []string{"ip6_gre"}},
	{Kind: KindIP6GRETAP, Title: "GRETAP over IPv6", Layer: 2, Under6: true, Carry4: true, Carry6: true, Overhead: 58, IPProto: 47, Lanes: true, Modules: []string{"ip6_gre"}},
	{Kind: KindIPIP6, Title: "IPIP6 (IPv4 in IPv6)", Layer: 3, Under6: true, Carry4: true, Overhead: 40, IPProto: 4, ConflictGroup: "ip6tnl", Modules: []string{"ip6_tunnel"}},
	{Kind: KindIP6IP6, Title: "IP6IP6 (IPv6 in IPv6)", Layer: 3, Under6: true, Carry6: true, Overhead: 40, IPProto: 41, ConflictGroup: "ip6tnl", Modules: []string{"ip6_tunnel"}},
	{Kind: KindVXLAN, Title: "VXLAN", Layer: 2, UnderAny: true, Carry4: true, Carry6: true, Overhead: 50, UDP: true, DefaultPort: 4789, HasVNI: true, Modules: []string{"vxlan"}, Hint: "layer 2 over UDP"},
	{Kind: KindGENEVE, Title: "GENEVE", Layer: 2, UnderAny: true, Carry4: true, Carry6: true, Overhead: 50, UDP: true, DefaultPort: 6081, HasVNI: true, Modules: []string{"geneve"}, Hint: "layer 2 over UDP, newer than VXLAN"},
	{Kind: KindL2TPv3, Title: "L2TPv3 (Ethernet pseudowire)", Layer: 2, UnderAny: true, Carry4: true, Carry6: true, Overhead: 38, IPProto: 115, PortEncap: true, Modules: []string{"l2tp_eth", "l2tp_netlink", "l2tp_ip", "l2tp_ip6"}, Hint: "layer 2 pseudowire over IP or UDP, MikroTik compatible"},
	{Kind: KindWireGuard, Title: "WireGuard", Layer: 3, UnderAny: true, Carry4: true, Carry6: true, Overhead: 60, UDP: true, Encrypted: true, NeedsPeer: false, DefaultPort: 51820, AutoPort: true, CarrierSuffix: "-w", Modules: []string{"wireguard"}, Hint: "encrypted in the kernel; also talks to MikroTik v7"},
	{Kind: KindEoIP, Title: "EoIP / EoIPv6 (MikroTik Ethernet over IP)", Layer: 2, UnderAny: true, Carry4: true, Carry6: true, Overhead: 42, IPProto: 47, PortEncap: true, Userspace: true, PMTU: true, Modules: []string{"tun"}, Hint: "MikroTik EoIP / EoIPv6: layer 2 over GRE, IPv6 or UDP"},
	{Kind: KindObfs, Title: "HLObfs (encrypted, obfuscated UDP)", Layer: 3, UnderAny: true, Carry4: true, Carry6: true, Overhead: ObfsOverhead, UDP: true, Encrypted: true, Userspace: true, NeedsPeer: true, AutoPort: true, HasPadding: true, HasObfsAES: true, CarrierSuffix: "-o", Modules: []string{"tun"}, Hint: "HLObfs: encrypted UDP that looks like random noise"},
	{Kind: KindSpoof, Title: "Spoof (forged source IP tunnel)", Layer: 3, Carry4: true, Carry6: true, Overhead: SpoofOverhead, UDP: true, Encrypted: true, Userspace: true, NeedsPeer: true, PMTU: true, DefaultPort: 32443, AutoPort: true, HasPadding: true, HasObfsAES: true, CarrierSuffix: "-s", Modules: []string{"tun"}, Hint: "forged-source-IP carrier over UDP, FakeTCP, GRE, IPIP, SIT or ICMP"},
	{Kind: KindTCP, Title: "TCP (packets over a TCP connection)", Layer: 3, UnderAny: true, Carry4: true, Carry6: true, Overhead: TCPOverhead, TCP: true, Userspace: true, NeedsPeer: true, AutoPort: true, Modules: []string{"tun"}, Hint: "packets over TCP: a last resort when UDP and GRE/SIT are blocked"},
	{Kind: KindStreamTCP, Title: "TCP + mux (connection tunnel)", UnderAny: true, TCP: true, Userspace: true, NeedsPeer: true, Stream: true, AutoPort: true, Hint: "TCP + mux: multiplexed connection tunnel over TCP"},
	{Kind: KindStreamTLS, Title: "TLS + mux (connection tunnel)", UnderAny: true, TCP: true, Encrypted: true, Userspace: true, NeedsPeer: true, Stream: true, AutoPort: true, Hint: "TLS + mux: multiplexed connection tunnel inside TLS"},
}

var kindByID = make(map[Kind]KindInfo, len(kinds))

func init() {
	for _, ki := range kinds {
		kindByID[ki.Kind] = ki
	}
}

// ObfsOverhead is HLObfs' per-packet cost over IPv4 without padding:
// IP 20 + UDP 8 + nonce 24 + tag 16 + header 14.
const ObfsOverhead = 82

// SpoofOverhead is Spoof's default per-packet cost over IPv4 UDP with AEAD:
// IP 20 + UDP 8 + nonce 24 + tag 16 + header 14.
const SpoofOverhead = 82

// SpoofOverheadFor returns the encapsulation cost of a Spoof tunnel for the
// chosen outer protocol ("udp", "tcp", "gre", "ipip", "sit", "icmp") and
// whether it runs in authenticated-only mode (noCrypt).
func SpoofOverheadFor(proto string, noCrypt bool) int {
	l4 := 8
	switch proto {
	case "tcp":
		l4 = 20
	case "ipip", "sit":
		l4 = 0
	}
	frame := 54
	if noCrypt {
		frame = 22
	}
	return 20 + l4 + frame
}

// TCPOverhead is the TCP transport's cost per packet over IPv4: IP 20 +
// TCP 32 (with timestamps) + length 2, shared by the packets of a segment;
// TCPTagOverhead is added with a cipher.
const (
	TCPOverhead    = 54
	TCPTagOverhead = 16
)

func Kinds() []KindInfo { return kinds }

func LookupKind(k Kind) (KindInfo, error) {
	if ki, ok := kindByID[k]; ok {
		return ki, nil
	}
	return KindInfo{}, fmt.Errorf("unknown tunnel kind %q", k)
}

// CanUsePort reports whether the kind can run on a chosen UDP/TCP port.
func (ki KindInfo) CanUsePort() bool { return ki.UDP || ki.TCP || ki.FOU || ki.PortEncap }

// IsGRE reports whether the kind carries a GRE key field.
func (ki KindInfo) IsGRE() bool { return ki.Lanes }

// EffectivePort returns p if non-zero, otherwise the kind's default port.
func (ki KindInfo) EffectivePort(p uint16) uint16 {
	if p != 0 {
		return p
	}
	return ki.DefaultPort
}

// PacketOverhead returns the per-packet encapsulation overhead of t alone.
// For MTU sizing, avgPad should be false (worst-case padding); for traffic
// estimation, avgPad may be true (mean padding).
func (t Tunnel) PacketOverhead(under6, keyless, avgPad bool) int {
	ki, err := LookupKind(t.Kind)
	if err != nil {
		return 0
	}
	var o int
	if t.Kind == KindSpoof {
		o = SpoofOverheadFor(t.SpoofProto, t.SpoofNoCrypt)
	} else {
		port := t.Port != 0 && t.Over == ""
		o = ki.OverheadFor(under6, port)
		if keyless && ki.IsGRE() {
			o -= 4
		}
		if t.Encrypt != "" {
			if ki.TCP {
				o += TCPTagOverhead
			} else {
				o += ESPOverhead
			}
		}
	}
	if ki.HasPadding {
		if avgPad {
			o += t.Padding / 2
		} else {
			o += t.Padding
		}
	}
	return o
}

// EffectiveEncrypt returns the encryption suite protecting a tunnel layer,
// covering both explicit IPsec/TCP ciphers and built-in kind encryption.
func (t Tunnel) EffectiveEncrypt() string {
	switch {
	case t.Encrypt != "":
		return t.Encrypt
	case t.Kind == KindWireGuard:
		return "wireguard"
	case t.Kind == KindObfs, t.Kind == KindSpoof && !t.SpoofNoCrypt:
		if t.ObfsAES {
			return "aes-gcm-128"
		}
		return "xchacha20-poly1305"
	}
	return ""
}

// OverheadFor returns the encapsulation cost given the underlay family and
// whether a port is in use (FOU for IP-protocol kinds, UDP encap for L2TPv3).
func (ki KindInfo) OverheadFor(under6, port bool) int {
	if ki.Kind == KindEoIP {
		return eoipOverhead(under6, port)
	}
	o := ki.Overhead
	if ki.IsGRE() {
		o += 4 // key field; we always set a key
	}
	if ki.UnderAny && under6 {
		o += 20
	}
	if port && ki.FOU {
		o += 8
	}
	if port && ki.PortEncap {
		o += 12 // UDP header + L2TPv3 UDP header
	}
	return o
}

// EtherIPProto is EoIPv6's outer IP protocol (EtherIP, RFC 3378).
const EtherIPProto = 97

// eoipOverhead: EoIP is outer IP + an 8-byte GRE header + the Ethernet
// header (42 over IPv4); EoIPv6 has a 2-byte EtherIP header instead (56).
// On a port the GRE-style header rides in UDP over either family.
func eoipOverhead(under6, port bool) int {
	ip := 20
	if under6 {
		ip = 40
	}
	switch {
	case port:
		return ip + 8 + 8 + 14
	case under6:
		return ip + 2 + 14
	}
	return ip + 8 + 14
}

// OuterProto is the IP protocol the kind's packets use without a port.
func (ki KindInfo) OuterProto(under6 bool) int {
	if ki.Kind == KindEoIP && under6 {
		return EtherIPProto
	}
	return ki.IPProto
}

// EoIPMaxID is the largest EoIP tunnel id the framing carries: 16 bits in
// EoIP's GRE header (also on a UDP port), 12 in raw EoIPv6's EtherIP header.
func EoIPMaxID(under6, port bool) uint16 {
	if under6 && !port {
		return 0x0fff
	}
	return 0xffff
}
