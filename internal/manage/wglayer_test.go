package manage

import (
	"testing"

	"hltunnel/internal/config"
)

// An Ethernet tunnel over WireGuard: kernel encryption inside UDP, for a
// path that drops ESP or GRE.
func TestPlanL2OverWireGuard(t *testing.T) {
	st := testState()
	for _, mode := range []string{"gretap", "vxlan", "eoip"} {
		_, defs, err := PlanTunnel(st, TunnelRequest{Peer: "edge", Mode: mode, WireGuard: true, Settings: Settings{Encrypt: "aes-gcm-128"}})
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if len(defs) != 2 {
			t.Fatalf("%s: want two layers, got %d", mode, len(defs))
		}
		wg, top := defs[0], defs[1]
		if wg.Kind != config.KindWireGuard || wg.Name != "t1-w" || wg.Port == 0 || wg.Encrypt != "" {
			t.Errorf("%s: bottom %+v", mode, wg)
		}
		if string(top.Kind) != mode || top.Over != "t1-w" || top.Encrypt != "" || top.AutoEncrypt || top.Sides[1].Endpoint != "" {
			t.Errorf("%s: top %+v", mode, top)
		}
	}
	for _, r := range []TunnelRequest{
		{Peer: "edge", Mode: "6to4", WireGuard: true},               // IP traffic: WireGuard itself
		{Peer: "edge", Mode: "gretap", WireGuard: true, Obfs: true}, // one layer
		{Remote: "203.0.113.9", Mode: "gretap", WireGuard: true},    // keys need HLTunnel there
	} {
		if _, _, err := PlanTunnel(st, r); err == nil {
			t.Errorf("planned %+v", r)
		}
	}
}
