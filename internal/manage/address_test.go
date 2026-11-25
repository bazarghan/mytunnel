package manage

import (
	"net/netip"
	"testing"

	"hltunnel/internal/config"
)

// addrState saves a main server on 192.0.2.1 with one tunnel to a peer
// that isn't paired (so nothing is pushed anywhere).
func addrState(t *testing.T, local bool) {
	t.Helper()
	config.Dir = t.TempDir()
	if _, err := config.Update(func(s *config.State) error {
		s.Self, s.Address, s.AddressLocal, s.AgentPort = "ir", "192.0.2.1", local, 7710
		s.Peers = []config.Peer{{Name: "de", Address: "198.51.100.1"}}
		s.Tunnels = []config.Tunnel{{Name: "t1", Kind: config.KindGRE,
			Sides: [2]config.Side{{Node: "ir", Endpoint: "192.0.2.1"}, {Node: "de", Endpoint: "198.51.100.1"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func ourEndpoint(t *testing.T) (string, *config.State) {
	t.Helper()
	st, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	return st.Tunnels[0].Sides[0].Endpoint, st
}

// Saving a new IP moves the tunnels too, and saving the one already there
// repairs tunnels an earlier version left on the old one.
func TestSetNodeMovesTunnels(t *testing.T) {
	defer func(d string) { config.Dir = d }(config.Dir)
	addrState(t, false)
	if _, err := SetNode("", "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	ep, st := ourEndpoint(t)
	if ep != "203.0.113.5" || st.Address != "203.0.113.5" {
		t.Errorf("address %s, tunnel side %s", st.Address, ep)
	}
	rev := st.Revision

	// As an older version left it: the address saved, the tunnel not moved.
	config.Update(func(s *config.State) error {
		s.Tunnels[0].Sides[0].Endpoint = "192.0.2.1"
		return nil
	})
	if _, err := SetNode("", "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if ep, st := ourEndpoint(t); ep != "203.0.113.5" || st.Revision == rev {
		t.Errorf("repair: tunnel side %s, revision %d (was %d)", ep, st.Revision, rev)
	}

	// Nothing to do: no new revision.
	_, st = ourEndpoint(t)
	rev = st.Revision
	if _, err := SetNode("", "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if _, st := ourEndpoint(t); st.Revision != rev {
		t.Errorf("an unchanged address made revision %d (was %d)", st.Revision, rev)
	}
	if _, err := SetNode("", "nope"); err == nil {
		t.Error("an invalid address was accepted")
	}
}

type fakeNet struct {
	local    map[netip.Addr]bool
	detected netip.Addr
}

func (n *fakeNet) watch() *AddressWatch {
	return &AddressWatch{
		local:  func(a netip.Addr) bool { return n.local[a] },
		detect: func(bool) netip.Addr { return n.detected },
	}
}

func TestAddressWatchFollowsNewIP(t *testing.T) {
	defer func(d string) { config.Dir = d }(config.Dir)
	addrState(t, false)
	old, now := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.5")
	n := &fakeNet{local: map[netip.Addr]bool{old: true}, detected: old}
	w := n.watch()

	// Still on the interface: it remembers that, and moves nothing.
	if to, _, _, err := w.Check(); err != nil || to != "" {
		t.Fatalf("check on the same IP: %q, %v", to, err)
	}
	if _, st := ourEndpoint(t); !st.AddressLocal {
		t.Error("the address on the interface wasn't recorded as local")
	}

	// The provider gives the server a new IP.
	n.local = map[netip.Addr]bool{now: true}
	n.detected = now
	if to, _, _, _ := w.Check(); to != "" {
		t.Errorf("moved to %s on the first check without the old IP", to)
	}
	to, moved, _, err := w.Check()
	if err != nil || to != now.String() || len(moved) != 1 || moved[0] != "t1" {
		t.Fatalf("second check: %q %v %v", to, moved, err)
	}
	if ep, st := ourEndpoint(t); ep != now.String() || st.Address != now.String() || !st.AddressLocal {
		t.Errorf("after the move: address %s (local %v), tunnel side %s", st.Address, st.AddressLocal, ep)
	}
	if to, _, _, _ := w.Check(); to != "" {
		t.Errorf("moved again, to %s", to)
	}
}

func TestAddressWatchLeavesNAT(t *testing.T) {
	defer func(d string) { config.Dir = d }(config.Dir)
	for _, c := range []struct {
		name     string
		local    bool // State.AddressLocal
		iface    []string
		detected string
	}{
		// Behind NAT: the public IP was never on the interface.
		{"nat", false, []string{"10.0.0.5"}, "10.0.0.5"},
		// It was, but the route now leaves from a private address.
		{"private", true, []string{"10.0.0.5"}, "10.0.0.5"},
		{"cgnat", true, []string{"100.64.1.2"}, "100.64.1.2"},
		// No route yet (the network is still coming up).
		{"no route", true, nil, ""},
	} {
		addrState(t, c.local)
		n := &fakeNet{local: map[netip.Addr]bool{}}
		for _, a := range c.iface {
			n.local[netip.MustParseAddr(a)] = true
		}
		if c.detected != "" {
			n.detected = netip.MustParseAddr(c.detected)
		}
		w := n.watch()
		for i := 0; i < GoneChecks+1; i++ {
			if to, _, _, err := w.Check(); to != "" || err != nil {
				t.Errorf("%s: moved to %q (%v)", c.name, to, err)
			}
		}
		if ep, st := ourEndpoint(t); ep != "192.0.2.1" || st.Address != "192.0.2.1" {
			t.Errorf("%s: address %s, tunnel side %s", c.name, st.Address, ep)
		}
	}
}

func TestPublic(t *testing.T) {
	for a, want := range map[string]bool{
		"203.0.113.5": true, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"100.64.0.1": false, "127.0.0.1": false, "169.254.1.1": false,
		"2001:db8::1": true, "fd00::1": false, "fe80::1": false, "::ffff:203.0.113.5": true,
	} {
		if got := Public(netip.MustParseAddr(a)); got != want {
			t.Errorf("Public(%s) = %v", a, got)
		}
	}
}
