package config

import (
	"slices"
	"testing"
	"time"
)

func twoMasters() *State {
	a := &Managed{Master: MasterRef{Name: "iran1", PublicKey: "KEYA"}, Self: "tr", Tunnels: []Tunnel{
		{Name: "t1-6", Kind: KindSIT, Sides: [2]Side{{Node: "iran1"}, {Node: "tr"}}, Net6: "fd77::/64"},
		{Name: "t1", Kind: KindIPIP6, Over: "t1-6", Sides: [2]Side{{Node: "iran1"}, {Node: "tr"}}, Net4: "10.77.0.0/30"},
		{Name: "g1", Kind: KindGRE, Sides: [2]Side{{Node: "iran1"}, {Node: "tr"}}, Net4: "10.77.0.4/30"},
	}, Forwards: []Forward{
		{Node: "iran1", Tunnel: "t1", Ports: "443", Mode: ForwardRelay},
		{Node: "iran1", Tunnel: "g1", Backup: "t1", Ports: "8443", Mode: ForwardRelay},
	}}
	b := &Managed{Master: MasterRef{Name: "iran2", PublicKey: "KEYB"}, Self: "tr-2", Tunnels: []Tunnel{
		{Name: "t1", Kind: KindGRE, Sides: [2]Side{{Node: "iran2"}, {Node: "tr-2"}}, Net4: "10.77.0.8/30"},
	}}
	return &State{Self: "tr", Managed: a, More: []*Managed{b}}
}

func running(st *State) []string {
	ts, _ := st.Effective()
	var out []string
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

// Dropping the 6to4 carrier drops the tunnel over it and the forward on
// it; a forward that only used it as a backup keeps running without it.
func TestDropManaged(t *testing.T) {
	st := twoMasters()
	got := st.Managed.Drop("t1-6")
	if !slices.Equal(got, []string{"t1-6", "t1"}) {
		t.Fatalf("dropped %v", got)
	}
	if r := running(st); !slices.Equal(r, []string{"g1", LocalName("t1", "KEYB")}) {
		t.Fatalf("running %v", r)
	}
	fs := st.AllForwards()
	if len(fs) != 1 || fs[0].Tunnel != "g1" || fs[0].Backup != "" {
		t.Fatalf("forwards %+v", fs)
	}
	if st.Managed.Drop("nope") != nil {
		t.Error("dropped a tunnel the master doesn't have")
	}

	// The master deletes one of them itself: the drop is no longer needed.
	st.Managed.Tunnels = st.Managed.Tunnels[1:]
	st.Managed.PruneDropped()
	if st.Managed.Dropped != nil {
		t.Errorf("kept %v", st.Managed.Dropped)
	}
	// t1 runs again: its carrier went with the master's change, not a drop.
	st = twoMasters()
	st.Managed.Drop("g1")
	st.Managed.Restore(nil)
	if len(running(st)) != 4 {
		t.Errorf("restore: %v", running(st))
	}
}

// Forgetting the first master leaves the second's tunnels under the names
// they run with, so its interfaces aren't rebuilt.
func TestForgetMaster(t *testing.T) {
	st := twoMasters()
	before := running(st)[3]
	if m := st.ForgetMaster("KEYA"); m == nil || m.Master.Name != "iran1" {
		t.Fatalf("forgot %+v", m)
	}
	if st.Managed == nil || st.Managed.Master.Name != "iran2" || st.More != nil || !st.Managed.Tagged {
		t.Fatalf("after: %+v %+v", st.Managed, st.More)
	}
	if r := running(st); !slices.Equal(r, []string{before}) {
		t.Fatalf("running %v, want %s", r, before)
	}
	if st.ForgetMaster("KEYA") != nil {
		t.Error("forgot it twice")
	}
	st.ForgetMaster("KEYB")
	if st.Managed != nil || len(st.Masters()) != 0 {
		t.Error("masters left")
	}
}

func TestSilentMasters(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	st := twoMasters()
	st.Managed.LastContact = now.Add(-31 * 24 * time.Hour)
	st.More[0].LastContact = now.Add(-2 * time.Hour)
	if s := st.SilentMasters(now); len(s) != 1 || s[0].Master.Name != "iran1" {
		t.Fatalf("silent %v", s)
	}
	st.Managed.Keep = true
	if len(st.SilentMasters(now)) != 0 {
		t.Error("kept master forgotten")
	}
	st.Managed.Keep, st.ForgetMasterDays = false, -1
	if len(st.SilentMasters(now)) != 0 || st.ForgetDays() != 0 {
		t.Error("forgetting is off")
	}
	st.ForgetMasterDays = 40
	if len(st.SilentMasters(now)) != 0 {
		t.Error("forgotten before 40 days")
	}
	// Not known yet (a node from before): never silent.
	st.ForgetMasterDays, st.Managed.LastContact = 0, time.Time{}
	if len(st.SilentMasters(now)) != 0 {
		t.Error("unknown contact counted as silence")
	}
}

func TestGone(t *testing.T) {
	now := time.Now()
	st := &State{}
	st.AddGone(Peer{Name: "de", PublicKey: "K1"}, now.Add(-31*24*time.Hour))
	st.AddGone(Peer{Name: "nl", PublicKey: "K2"}, now)
	st.AddGone(Peer{Name: "nl", PublicKey: "K2"}, now)
	if len(st.Gone) != 2 {
		t.Fatalf("gone %+v", st.Gone)
	}
	st.ExpireGone(now)
	if len(st.Gone) != 1 || st.Gone[0].Peer.Name != "nl" {
		t.Fatalf("after expiry %+v", st.Gone)
	}
	st.DropGone("K2")
	if st.Gone != nil {
		t.Error("not dropped")
	}
}
