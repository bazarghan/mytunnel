package config

import (
	"slices"
	"testing"
)

func TestMoveAddress(t *testing.T) {
	far := Side{Node: "de", Endpoint: "198.51.100.1"}
	s := &State{Self: "ir", Address: "192.0.2.1", Tunnels: []Tunnel{
		{Name: "gre", Sides: [2]Side{{Node: "ir", Endpoint: "192.0.2.1"}, far}},
		// The far end's side, here side 0: never ours to move.
		{Name: "back", Sides: [2]Side{far, {Node: "ir", Endpoint: "192.0.2.1", Local: "192.0.2.1"}}},
		// Saved before an earlier change of the address that didn't move it.
		{Name: "stale", Sides: [2]Side{{Node: "ir", Endpoint: "192.0.2.9"}, far}},
		// Behind NAT: the source override is the private address, which stays.
		{Name: "nat", Sides: [2]Side{{Node: "ir", Endpoint: "192.0.2.1", Local: "10.0.0.5"}, far}},
		{Name: "v6", Sides: [2]Side{{Node: "ir", Endpoint: "2001:db8::1"}, {Node: "de", Endpoint: "2001:db8::2"}}},
		{Name: "over", Over: "gre", Sides: [2]Side{{Node: "ir"}, {Node: "de"}}},
		{Name: "done", Sides: [2]Side{{Node: "ir", Endpoint: "203.0.113.5"}, far}},
	}}
	if !s.StaleAddress() {
		t.Error("StaleAddress missed the tunnel left on 192.0.2.9")
	}
	if s.Tunnels[2].Sides[0].Endpoint != "192.0.2.9" {
		t.Fatal("StaleAddress changed the state")
	}
	moved := s.MoveAddress("203.0.113.5")
	if want := []string{"gre", "back", "stale", "nat"}; !slices.Equal(moved, want) {
		t.Errorf("moved %v, want %v", moved, want)
	}
	if s.Address != "203.0.113.5" {
		t.Errorf("address %q", s.Address)
	}
	for _, c := range []struct {
		tunnel      string
		side        int
		ep, local   string
		description string
	}{
		{"gre", 0, "203.0.113.5", "", "our side"},
		{"gre", 1, "198.51.100.1", "", "far side"},
		{"back", 1, "203.0.113.5", "203.0.113.5", "our side 1 with the old address as source"},
		{"back", 0, "198.51.100.1", "", "far side 0"},
		{"stale", 0, "203.0.113.5", "", "stale side"},
		{"nat", 0, "203.0.113.5", "10.0.0.5", "NAT source"},
		{"v6", 0, "2001:db8::1", "", "IPv6 underlay"},
		{"over", 0, "", "", "stacked tunnel"},
	} {
		tn, _ := s.Tunnel(c.tunnel)
		if sd := tn.Sides[c.side]; sd.Endpoint != c.ep || sd.Local != c.local {
			t.Errorf("%s: %+v, want endpoint %q local %q", c.description, sd, c.ep, c.local)
		}
	}
	if s.StaleAddress() {
		t.Error("still stale after the move")
	}
	if moved := s.MoveAddress("not an ip"); moved != nil || s.Address != "203.0.113.5" {
		t.Errorf("an invalid address moved %v to %q", moved, s.Address)
	}
}
