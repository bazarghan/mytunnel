package mikrotik

import (
	"strings"
	"testing"

	"hltunnel/internal/config"
	"hltunnel/internal/engine"
)

const (
	server = "203.0.113.1"
	router = "198.51.100.7"
	secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)

func remote(name string, kind config.Kind) config.Tunnel {
	return config.Tunnel{Name: name, Kind: kind,
		Sides: [2]config.Side{{Node: "ir1", Endpoint: server}, {Endpoint: router}},
		Net4:  "10.77.0.4/30", Key: 0x12345678, Secret: secret}
}

func u16(v uint16) *uint16 { return &v }

func TestCommands(t *testing.T) {
	sit := remote("mk-6", config.KindSIT)
	sit.Net4, sit.Net6 = "", "fd00:1:2:3::/64"
	ipip6 := remote("mk", config.KindIPIP6)
	ipip6.Over, ipip6.Mode, ipip6.Sides[0].Endpoint, ipip6.Sides[1].Endpoint = "mk-6", "6to4", "", ""

	eoip := remote("eo", config.KindEoIP)
	eoip.TunnelID = u16(42)
	eoip6 := remote("eo6", config.KindEoIP)
	eoip6.Sides[0].Endpoint, eoip6.Sides[1].Endpoint = "2001:db8::1", "2001:db8::2"

	vx := remote("vx", config.KindVXLAN)
	vx.VNI = 4242
	l2 := remote("l2", config.KindL2TPv3)
	l2u := remote("l2u", config.KindL2TPv3)
	l2u.Port = 1701

	wg := remote("wg", config.KindWireGuard)
	wg.Port, wg.Net6 = 51821, "fd00:1:2:4::/64"
	wg.PeerKey = "cm91dGVyLXB1YmxpYy1rZXktMzItYnl0ZXMtbG9uZyE="
	wgOff := remote("wgk", config.KindWireGuard)
	wgOff.Port, wgOff.Keepalive = 51822, -1

	gre := remote("gre", config.KindGRE)
	gre.DSCP = 46

	tests := []struct {
		name    string
		tunnels []config.Tunnel
		forward []config.Forward
		want    string
	}{
		{"gre", []config.Tunnel{gre}, nil, `# HLTunnel gre (gre): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
/interface gre add name=hl-gre remote-address=203.0.113.1 mtu=1476 dscp=46 comment="HLTunnel gre"
/ip address add address=10.77.0.6/30 interface=hl-gre comment="HLTunnel gre"
`},
		{"ipip with forwards", []config.Tunnel{remote("ip", config.KindIPIP)}, []config.Forward{
			{Node: "ir1", Tunnel: "ip", Proto: "tcp", Ports: "443,8080-8090"},
			{Node: "ir1", Tunnel: "ip", Proto: "both", Ports: "2053", To: 53, Mode: config.ForwardProxy},
		}, `# HLTunnel ip (ipip): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
/interface ipip add name=hl-ip remote-address=203.0.113.1 mtu=1480 comment="HLTunnel ip"
/ip address add address=10.77.0.6/30 interface=hl-ip comment="HLTunnel ip"
# Ports forwarded here arrive on 10.77.0.6 from 10.77.0.5 (connected, no route needed):
#   tcp 443,8080-8090 -> same port
#   both 2053 -> port 53, with a PROXY protocol v2 header
# to pass them on to a host behind the router, e.g.:
# /ip firewall nat add chain=dstnat in-interface=hl-ip protocol=tcp dst-port=443,8080-8090 action=dst-nat to-addresses=192.168.88.10
`},
		{"6to4 stack", []config.Tunnel{sit, ipip6}, nil, `# HLTunnel mk (6to4): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
/interface 6to4 add name=hl-mk-6 remote-address=203.0.113.1 mtu=1480 comment="HLTunnel mk-6"
/interface ipipv6 add name=hl-mk remote-address=fd00:1:2:3::1 local-address=fd00:1:2:3::2 mtu=1440 comment="HLTunnel mk"
/ipv6 address add address=fd00:1:2:3::2/64 interface=hl-mk-6 advertise=no comment="HLTunnel mk-6"
/ip address add address=10.77.0.6/30 interface=hl-mk comment="HLTunnel mk"
`},
		{"eoip", []config.Tunnel{eoip}, nil, `# HLTunnel eo (eoip): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
/interface eoip add name=hl-eo remote-address=203.0.113.1 tunnel-id=42 mtu=1458 comment="HLTunnel eo"
/ip address add address=10.77.0.6/30 interface=hl-eo comment="HLTunnel eo"
`},
		{"eoipv6", []config.Tunnel{eoip6}, nil, `# HLTunnel eo6 (eoip): RouterOS v7 commands for the router at 2001:db8::2
# HLTunnel server: 2001:db8::1
/interface eoipv6 add name=hl-eo6 remote-address=2001:db8::1 tunnel-id=1656 mtu=1444 comment="HLTunnel eo6"
/ip address add address=10.77.0.6/30 interface=hl-eo6 comment="HLTunnel eo6"
`},
		{"vxlan", []config.Tunnel{vx}, nil, `# HLTunnel vx (vxlan): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
/interface vxlan add name=hl-vx vni=4242 port=4789 mtu=1450 comment="HLTunnel vx"
/interface vxlan vteps add interface=hl-vx remote-ip=203.0.113.1
/ip address add address=10.77.0.6/30 interface=hl-vx comment="HLTunnel vx"
`},
		{"l2tpv3 ip", []config.Tunnel{l2}, nil, `# HLTunnel l2 (l2tpv3): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
# local-address is the router's own address; behind NAT, use the address on its WAN interface
/interface l2tp-ether add name=hl-l2 connect-to=203.0.113.1 local-address=198.51.100.7 unmanaged-mode=yes l2tp-proto-version=l2tpv3-ip local-tunnel-id=305419896 remote-tunnel-id=305419896 local-session-id=305419896 remote-session-id=305419896 mtu=1462 disabled=no comment="HLTunnel l2"
/ip address add address=10.77.0.6/30 interface=hl-l2 comment="HLTunnel l2"
`},
		{"l2tpv3 udp", []config.Tunnel{l2u}, nil, `# HLTunnel l2u (l2tpv3): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
# local-address is the router's own address; behind NAT, use the address on its WAN interface
/interface l2tp-ether add name=hl-l2u connect-to=203.0.113.1 local-address=198.51.100.7 unmanaged-mode=yes l2tp-proto-version=l2tpv3-udp local-tunnel-id=305419896 remote-tunnel-id=305419896 local-session-id=305419896 remote-session-id=305419896 mtu=1450 disabled=no comment="HLTunnel l2u"
/ip address add address=10.77.0.6/30 interface=hl-l2u comment="HLTunnel l2u"
`},
		{"wireguard", []config.Tunnel{wg}, nil, `# HLTunnel wg (wireguard): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
/interface wireguard add name=hl-wg listen-port=51821 mtu=1440 comment="HLTunnel wg"
/interface wireguard peers add interface=hl-wg public-key="WG_PUB" endpoint-address=203.0.113.1 endpoint-port=51821 allowed-address=10.77.0.5/32,fd00:1:2:4::1/128 persistent-keepalive=25s comment="HLTunnel wg"
# HLTunnel expects the router's public key cm91dGVyLXB1YmxpYy1rZXktMzItYnl0ZXMtbG9uZyE=;
# if the router made a different one, give HLTunnel this key as the peer key:
:put [/interface wireguard get hl-wg public-key]
/ip address add address=10.77.0.6/30 interface=hl-wg comment="HLTunnel wg"
/ipv6 address add address=fd00:1:2:4::2/64 interface=hl-wg advertise=no comment="HLTunnel wg"
`},
		{"wireguard no keepalive", []config.Tunnel{wgOff}, nil, `# HLTunnel wgk (wireguard): RouterOS v7 commands for the router at 198.51.100.7
# HLTunnel server: 203.0.113.1
/interface wireguard add name=hl-wgk listen-port=51822 mtu=1440 comment="HLTunnel wgk"
/interface wireguard peers add interface=hl-wgk public-key="WG_PUB" endpoint-address=203.0.113.1 endpoint-port=51822 allowed-address=10.77.0.5/32 comment="HLTunnel wgk"
# give HLTunnel the router's public key (peer key):
:put [/interface wireguard get hl-wgk public-key]
/ip address add address=10.77.0.6/30 interface=hl-wgk comment="HLTunnel wgk"
`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &config.State{Self: "ir1", Tunnels: tc.tunnels, Forwards: tc.forward}
			top := tc.tunnels[len(tc.tunnels)-1]
			got, err := Commands(st, top.Name)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.want
			if top.Kind == config.KindWireGuard {
				want = strings.ReplaceAll(want, "WG_PUB", wgPub(t, top))
			}
			if got != want {
				t.Errorf("got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestCommandsRefuses(t *testing.T) {
	peer := remote("pe", config.KindGRE)
	peer.Sides[1].Node = "de1"
	fou := remote("fou", config.KindGRE)
	fou.Port = 5555
	eoUDP := remote("eou", config.KindEoIP)
	eoUDP.Port = 5556
	tests := []struct {
		name string
		t    config.Tunnel
		want string
	}{
		{"managed peer", peer, "configures itself"},
		{"fou", fou, "FOU"},
		{"eoip on udp", eoUDP, "only HLTunnel"},
		{"gretap", remote("gt", config.KindGRETAP), "no GRETAP"},
		{"geneve", remote("gn", config.KindGENEVE), "no geneve"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &config.State{Self: "ir1", Tunnels: []config.Tunnel{tc.t}}
			_, err := Commands(st, tc.t.Name)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	if _, err := Commands(&config.State{Self: "ir1"}, "nope"); err == nil {
		t.Fatal("unknown tunnel: no error")
	}
}

func wgPub(t *testing.T, tn config.Tunnel) string {
	t.Helper()
	k, err := engine.WireGuardPublicKey(tn, 0)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
