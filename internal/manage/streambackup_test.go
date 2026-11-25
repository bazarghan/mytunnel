package manage

import (
	"strings"
	"testing"

	"hltunnel/internal/config"
)

func TestStreamBackupCheck(t *testing.T) {
	b := config.Tunnel{Name: "t2", Kind: config.KindStreamTCP, Port: 9443, Secret: "s",
		Sides: [2]config.Side{{Node: "hub"}, {Node: "edge", Endpoint: "203.0.113.9"}}}
	st := &config.State{Self: "hub", Tunnels: []config.Tunnel{b}}
	for _, c := range []struct {
		r    ForwardRequest
		want string
	}{
		{ForwardRequest{Mode: "nat", Proto: "both", Ports: "443"}, ""},
		{ForwardRequest{Mode: "", Proto: "tcp", Ports: "443"}, ""},
		{ForwardRequest{Mode: "proxy", Proto: "tcp", Ports: "2053-2096"}, ""},
		{ForwardRequest{Mode: "transparent", Proto: "tcp", Ports: "443"}, ""},
		{ForwardRequest{Mode: "relay", Proto: "tcp", Ports: "443"}, ""},
		{ForwardRequest{Mode: "nat", Proto: "udp", Ports: "443"}, "TCP only"},
		{ForwardRequest{Mode: "nat", Proto: "tcp", Ports: "1-3000"}, "up to"},
		{ForwardRequest{Mode: "nat", Proto: "tcp", Ports: "9443"}, "itself listens"},
	} {
		err := checkStreamBackup(st, c.r, b)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%+v: %v", c.r, err)
		}
	}
	// A far server too old to take the connections.
	st.Peers = []config.Peer{{Name: "edge", PublicKey: "k"}}
	if p, _ := st.Peer("edge"); !p.Paired() {
		t.Skip("peer fixture isn't paired")
	}
	if err := checkStreamBackup(st, ForwardRequest{Mode: "nat", Proto: "tcp", Ports: "443"}, b); err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("old peer: %v", err)
	}
}
