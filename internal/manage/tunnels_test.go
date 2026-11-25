package manage

import (
	"testing"

	"hltunnel/internal/config"
)

func testState() *config.State {
	return &config.State{Self: "hub", Address: "198.51.100.1", Peers: []config.Peer{{Name: "edge", Address: "203.0.113.2"}}}
}

func TestPlanTCPTunnel(t *testing.T) {
	st := testState()
	name, defs, err := PlanTunnel(st, TunnelRequest{Peer: "edge", Mode: "tcp", Settings: Settings{Encrypt: "aes-gcm-256"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 1 {
		t.Fatalf("want one tunnel, got %d", len(defs))
	}
	d := defs[0]
	if d.Name != name || d.Kind != config.KindTCP || d.Port < 31443 || d.Encrypt != "aes-gcm-256" || !d.NeedsSecret() {
		t.Errorf("tcp tunnel: %+v", d)
	}

	if _, _, err := PlanTunnel(st, TunnelRequest{Peer: "edge", Mode: "tcp", Obfs: true}); err == nil {
		t.Error("TCP over HLObfs was planned")
	}
	if _, _, err := PlanTunnel(st, TunnelRequest{Remote: "203.0.113.9", Mode: "tcp"}); err == nil {
		t.Error("TCP to a device without HLTunnel was planned")
	}
	if _, _, err := PlanTunnel(st, TunnelRequest{Peer: "edge", Mode: "tcp", Port: 7710}); err == nil {
		t.Error("TCP on the agent's port was planned")
	}
}

func TestFreePortSkipsUsedPorts(t *testing.T) {
	st := testState()
	st.Tunnels = []config.Tunnel{{Name: "o", Kind: config.KindObfs, Port: 31443, Sides: [2]config.Side{{Node: "hub"}, {Node: "edge"}}}}
	if p := FreePort(st, config.KindTCP, ""); p != 31444 {
		t.Errorf("got port %d", p)
	}
}

func TestNewTunnelChecksEoIPTunnelID(t *testing.T) {
	id := func(v uint16) *uint16 { return &v }
	st := &config.State{Self: "a", Address: "2001:db8::1"}
	cases := []struct {
		kind, remote string
		port         uint16
		id           *uint16
		ok           bool
	}{
		{"eoip", "203.0.113.10", 0, id(65535), true},
		{"eoip", "2001:db8::2", 0, id(4095), true},
		{"eoip", "2001:db8::2", 0, id(4096), false},
		{"eoip", "2001:db8::2", 4000, id(4096), true},
		{"gre", "203.0.113.10", 0, id(1), false},
	}
	for _, c := range cases {
		o := TunnelOpts{Kind: c.kind, Remote: c.remote, Port: c.port}
		o.TunnelID = c.id
		tn, err := NewTunnel(st, "e1", o)
		if (err == nil) != c.ok {
			t.Errorf("%s to %s port %d id %d: err %v", c.kind, c.remote, c.port, *c.id, err)
		}
		if err == nil && (tn.TunnelID == nil || *tn.TunnelID != *c.id) {
			t.Errorf("%s to %s: tunnel id %v not kept", c.kind, c.remote, tn.TunnelID)
		}
	}
}

func TestRandomPortAvoidsUsedPorts(t *testing.T) {
	st := testState()
	st.Tunnels = []config.Tunnel{{Name: "o", Kind: config.KindObfs, Port: 30443, Sides: [2]config.Side{{Node: "hub"}, {Node: "edge"}}}}
	for range 50 {
		p, err := RandomPort(st, "udp")
		if err != nil {
			t.Fatal(err)
		}
		if p < 20000 || p > 60000 || p == 30443 {
			t.Fatalf("got port %d", p)
		}
	}
}

func TestSpoofPinholePlanningAndValidation(t *testing.T) {
	st := testState()

	// Valid combinations.
	for _, tc := range []struct {
		name string
		req  TunnelRequest
	}{
		{"auto", TunnelRequest{Peer: "edge", Mode: "spoof", Settings: Settings{SpoofProto: "udp", SpoofSrc: "auto", SpoofPinhole: true, SpoofPinholeInterval: 15}}},
		{"out_iran", TunnelRequest{Peer: "edge", Mode: "spoof", Settings: Settings{SpoofMode: "out", SpoofSrc: "iran", SpoofPinhole: true}}},
		{"pair_static_remote", TunnelRequest{Peer: "edge", Mode: "spoof", Settings: Settings{SpoofSrc: "iran,8.8.8.8", SpoofPinhole: true, SpoofPinholeInterval: 20}}},
		{"stacked_6to4", TunnelRequest{Peer: "edge", Mode: "6to4", Spoof: true, Settings: Settings{SpoofProto: "tcp", SpoofSrc: "auto", SpoofPinhole: true, SpoofPinholeInterval: 12}}},
	} {
		t.Run("valid_"+tc.name, func(t *testing.T) {
			_, defs, err := PlanTunnel(st, tc.req)
			if err != nil {
				t.Fatalf("PlanTunnel(%s) unexpected error: %v", tc.name, err)
			}
			bottom := defs[0]
			if bottom.Kind != config.KindSpoof || !bottom.SpoofPinhole || bottom.SpoofPinholeInterval != tc.req.SpoofPinholeInterval {
				t.Fatalf("unexpected bottom tunnel: %+v", bottom)
			}
			tmp := *st
			tmp.Tunnels = defs
			topName := defs[len(defs)-1].Name
			got, _ := SettingsOf(&tmp, topName)
			if !got.SpoofPinhole || got.SpoofPinholeInterval != tc.req.SpoofPinholeInterval {
				t.Fatalf("SettingsOf mismatch: %+v", got)
			}
		})
	}

	// Invalid combinations.
	for _, tc := range []struct {
		name string
		s    Settings
	}{
		{"both_iran", Settings{SpoofMode: "both", SpoofSrc: "iran", SpoofPinhole: true}},
		{"both_rotate", Settings{SpoofMode: "both", SpoofSrc: "rotate", SpoofPinhole: true}},
		{"pair_remote_iran", Settings{SpoofSrc: "8.8.8.8,iran", SpoofPinhole: true}},
		{"neg_interval", Settings{SpoofPinhole: true, SpoofPinholeInterval: -1}},
		{"huge_interval", Settings{SpoofPinhole: true, SpoofPinholeInterval: 3601}},
	} {
		t.Run("invalid_"+tc.name, func(t *testing.T) {
			if err := tc.s.validate(); err == nil {
				t.Fatalf("Settings(%s).validate() = nil, want error", tc.name)
			}
		})
	}
}
