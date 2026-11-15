package forward

import (
	"strings"
	"testing"

	"neotunnel/internal/config"
	"neotunnel/internal/failover"
)

// backupState has two tunnels between hub and edge: t1 and its backup t2.
func backupState(mode string) *config.State {
	st := modeState()
	st.Tunnels = append(st.Tunnels, config.Tunnel{
		Name: "t2", Kind: config.KindGRE, Net4: "10.77.0.4/30",
		Sides: [2]config.Side{{Node: "hub"}, {Node: "edge", Endpoint: "203.0.113.9"}},
	})
	st.Tunnels[0].Sides[1].Endpoint = "203.0.113.9"
	for i := range st.Tunnels {
		st.Tunnels[i].Secret = config.NewSecret()
	}
	st.Forwards = []config.Forward{{Node: "hub", Tunnel: "t1", Backup: "t2", Proto: "tcp", Ports: "443", Mode: mode}}
	return st
}

// While failed over, the forward's DNAT goes to the backup's far end.
func TestFailedOverForwardTargetsBackup(t *testing.T) {
	st := backupState("")
	links := []Link{{Name: "nt-t1", Tunnel: "t1"}, {Name: "nt-t2", Tunnel: "t2"}}
	ts, fs := st.Effective()
	rs, errs := Build(st, failover.Route(fs, ts, failover.Paths{}), links)
	if len(errs) > 0 || len(rs.Rules) != 1 || rs.Rules[0].Iface != "nt-t1" {
		t.Fatalf("primary: %v %+v", errs, rs.Rules)
	}
	ps := failover.Paths{failover.Key(fs[0]): {Active: "t2"}}
	rs, errs = Build(st, failover.Route(fs, ts, ps), links)
	if len(errs) > 0 || len(rs.Rules) != 1 || rs.Rules[0].Iface != "nt-t2" {
		t.Fatalf("backup: %v %+v", errs, rs.Rules)
	}
	s := Script(rs)
	for _, want := range []string{"tcp dport { 443 } dnat ip to 10.77.0.6", `oifname "nt-t2" ct status dnat masquerade`} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q:\n%s", want, s)
		}
	}
	// The counters stay the forward's, whichever tunnel carries it.
	if rs.Rules[0].Key != "tcp/443" {
		t.Errorf("key %q", rs.Rules[0].Key)
	}
}

// The far end can't tell when the near end fails over, so it keeps a return
// path (transparent) or an exit (relay) on both tunnels.
func TestFarEndServesBothTunnels(t *testing.T) {
	for _, mode := range []string{config.ForwardTransparent, config.ForwardRelay} {
		hub := backupState(mode)
		ts, fs := hub.ForPeer("edge")
		if len(fs) != 1 {
			t.Fatalf("%s: forward not sent to the far end", mode)
		}
		edge := &config.State{Self: "edge", Managed: &config.Managed{Self: "edge", Tunnels: ts, Forwards: fs}}
		_, own := edge.Effective()
		rs, errs := Build(edge, own, []Link{{Name: "nt-t1", Tunnel: "t1"}, {Name: "nt-t2", Tunnel: "t2"}})
		if len(errs) > 0 {
			t.Fatalf("%s: %v", mode, errs)
		}
		switch mode {
		case config.ForwardTransparent:
			if len(rs.Returns) != 2 || rs.Returns[1].Iface != "nt-t2" {
				t.Errorf("returns %+v", rs.Returns)
			}
		case config.ForwardRelay:
			if len(rs.Exits) != 2 || rs.Exits[1].Tunnel != "t2" || rs.Exits[1].Ports[0] != 443 {
				t.Errorf("exits %+v", rs.Exits)
			}
		}
	}
}

// A peer gets a transparent forward even when only its backup tunnel runs
// there.
func TestForPeerFollowsBackup(t *testing.T) {
	hub := backupState(config.ForwardTransparent)
	hub.Tunnels[1].Sides[1].Node = "other"
	hub.Forwards[0].Tunnel = "t2"
	hub.Forwards[0].Backup = "t1"
	if _, fs := hub.ForPeer("edge"); len(fs) != 1 {
		t.Fatalf("edge should get the forward its backup runs to")
	}
}

// streamBackupState is backupState with t2 a connection tunnel.
func streamBackupState(mode, proto string) *config.State {
	st := backupState(mode)
	st.Tunnels[1].Kind, st.Tunnels[1].Net4, st.Tunnels[1].Port = config.KindStreamTCP, "", 9443
	st.Forwards[0].Proto = proto
	return st
}

// A nat, transparent or proxy forward that moved to a connection tunnel
// relays its TCP over the sessions, and its far end takes those
// connections on the connection tunnel only.
func TestFallbackToConnectionTunnelRelays(t *testing.T) {
	for _, c := range []struct {
		mode    string
		version int
	}{{"", 0}, {config.ForwardTransparent, 0}, {config.ForwardProxy, 2}} {
		hub := streamBackupState(c.mode, "both")
		ts, fs := hub.Effective()
		ps := failover.Paths{failover.Key(fs[0]): {Active: "t2"}}
		rs, errs := Build(hub, failover.Route(fs, ts, ps), []Link{{Name: "nt-t1", Tunnel: "t1"}})
		if len(errs) > 0 || len(rs.Rules) != 0 || len(rs.Relays) != 1 {
			t.Fatalf("%q: %v, %d rules, %+v", c.mode, errs, len(rs.Rules), rs.Relays)
		}
		r := rs.Relays[0]
		if r.Proto != "tcp" || r.Port != 443 || r.Target.String() != "127.0.0.1:443" || r.Version != c.version || r.Via.Session != "t2" {
			t.Errorf("%q: relay %+v", c.mode, r)
		}
		// Back on t1 it is the kernel's again.
		rs, errs = Build(hub, failover.Route(fs, ts, failover.Paths{}), []Link{{Name: "nt-t1", Tunnel: "t1"}})
		// (A proxy forward's relay on t1 goes to the inner address, TCP and UDP.)
		kernel := len(rs.Rules) == 1 && len(rs.Relays) == 0
		if c.mode == config.ForwardProxy {
			kernel = len(rs.Relays) == 2 && rs.Relays[0].Via.Session == "" && rs.Relays[0].Target.Addr().String() == "10.77.0.2"
		}
		if len(errs) > 0 || !kernel {
			t.Fatalf("%q primary: %v %+v %+v", c.mode, errs, rs.Rules, rs.Relays)
		}

		ets, efs := hub.ForPeer("edge")
		if len(efs) != 1 {
			t.Fatalf("%q: forward not sent to the far end", c.mode)
		}
		edge := &config.State{Self: "edge", Managed: &config.Managed{Self: "edge", Tunnels: ets, Forwards: efs}}
		_, own := edge.Effective()
		rs, _ = Build(edge, own, []Link{{Name: "nt-t1", Tunnel: "t1"}})
		if len(rs.Exits) != 1 || rs.Exits[0].Tunnel != "t2" || !rs.Exits[0].Session || rs.Exits[0].Ports[0] != 443 {
			t.Errorf("%q: exits %+v", c.mode, rs.Exits)
		}
	}
}

// UDP has no way over a connection tunnel.
func TestFallbackToConnectionTunnelSkipsUDP(t *testing.T) {
	hub := streamBackupState("", "udp")
	ts, fs := hub.Effective()
	ps := failover.Paths{failover.Key(fs[0]): {Active: "t2"}}
	rs, errs := Build(hub, failover.Route(fs, ts, ps), nil)
	if len(errs) != 1 || len(rs.Relays) != 0 || len(rs.Rules) != 0 {
		t.Fatalf("%v %+v %+v", errs, rs.Rules, rs.Relays)
	}
	ets, efs := hub.ForPeer("edge")
	edge := &config.State{Self: "edge", Managed: &config.Managed{Self: "edge", Tunnels: ets, Forwards: efs}}
	_, own := edge.Effective()
	if rs, _ := Build(edge, own, nil); len(rs.Exits) != 0 {
		t.Errorf("exits %+v", rs.Exits)
	}
}
