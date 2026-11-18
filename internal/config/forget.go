package config

import (
	"slices"
	"time"
)

// Cleaning up after a server that is gone: a master forgotten here, a
// master's tunnel removed here by hand, a removed peer still to be told.

const (
	// DefaultForgetMasterDays is how long a master may stay silent before
	// this node forgets it and its tunnels.
	DefaultForgetMasterDays = 30
	// WarnSilentDays is when the panel starts saying a master is silent.
	WarnSilentDays = 7
	// GoneKeep is how long a removed peer is told again to drop our tunnels.
	GoneKeep = 30 * 24 * time.Hour
)

// dropped is the master's tunnels removed here by hand, and the tunnels
// that run over one of them (an ipip6 over a dropped sit).
func (m *Managed) dropped() map[string]bool {
	out := map[string]bool{}
	for _, n := range m.Dropped {
		out[n] = true
	}
	if len(out) == 0 {
		return out
	}
	for grew := true; grew; {
		grew = false
		for _, t := range m.Tunnels {
			if !out[t.Name] && t.Over != "" && out[t.Over] {
				out[t.Name], grew = true, true
			}
		}
	}
	return out
}

// Drop removes a master's tunnel (its name for it) on this node only, with
// those over it. It reports the names dropped; none when the master has
// no such tunnel.
func (m *Managed) Drop(name string) []string {
	if !slices.ContainsFunc(m.Tunnels, func(t Tunnel) bool { return t.Name == name }) {
		return nil
	}
	if !slices.Contains(m.Dropped, name) {
		m.Dropped = append(m.Dropped, name)
	}
	var out []string
	d := m.dropped()
	for _, t := range m.Tunnels {
		if d[t.Name] {
			out = append(out, t.Name)
		}
	}
	return out
}

// Restore lets the master's tunnels dropped by hand run again (none =
// all).
func (m *Managed) Restore(names []string) {
	if len(names) == 0 {
		m.Dropped = nil
		return
	}
	m.Dropped = slices.DeleteFunc(m.Dropped, func(n string) bool { return slices.Contains(names, n) })
}

// PruneDropped forgets drops of tunnels the master no longer has: once it
// deletes one itself there's nothing left to keep off.
func (m *Managed) PruneDropped() {
	m.Dropped = slices.DeleteFunc(m.Dropped, func(n string) bool {
		return !slices.ContainsFunc(m.Tunnels, func(t Tunnel) bool { return t.Name == n })
	})
	if len(m.Dropped) == 0 {
		m.Dropped = nil
	}
}

// ForgetMaster removes the master with key and everything it set up here.
// When the first master goes, the next takes its place and keeps its local
// names (Tagged), so its interfaces aren't rebuilt. It reports the master
// forgotten, nil if there is none with that key.
func (s *State) ForgetMaster(key string) *Managed {
	if s.Managed != nil && s.Managed.Master.PublicKey == key {
		m := s.Managed
		s.Managed = nil
		if len(s.More) > 0 {
			next := s.More[0]
			next.Tagged = true
			s.Managed, s.More = next, s.More[1:]
		}
		if len(s.More) == 0 {
			s.More = nil
		}
		return m
	}
	for i, m := range s.More {
		if m != nil && m.Master.PublicKey == key {
			s.More = slices.Delete(s.More, i, i+1)
			if len(s.More) == 0 {
				s.More = nil
			}
			return m
		}
	}
	return nil
}

// ForgetDays is ForgetMasterDays resolved: 0 = never.
func (s *State) ForgetDays() int {
	switch {
	case s.ForgetMasterDays < 0:
		return 0
	case s.ForgetMasterDays == 0:
		return DefaultForgetMasterDays
	}
	return s.ForgetMasterDays
}

// Silence is how long a master hasn't reached this node (0 when unknown).
func (m *Managed) Silence(now time.Time) time.Duration {
	if m.LastContact.IsZero() {
		return 0
	}
	return now.Sub(m.LastContact)
}

// SilentMasters lists the masters silent long enough to be forgotten now.
func (s *State) SilentMasters(now time.Time) []*Managed {
	days := s.ForgetDays()
	if days == 0 {
		return nil
	}
	var out []*Managed
	for _, m := range s.Masters() {
		if !m.Keep && m.EnrollToken == "" && m.Silence(now) >= time.Duration(days)*24*time.Hour {
			out = append(out, m)
		}
	}
	return out
}

// AddGone keeps p to be told later to drop our tunnels; a newer entry for
// the same server replaces the older one.
func (s *State) AddGone(p Peer, now time.Time) {
	s.DropGone(p.PublicKey)
	s.Gone = append(s.Gone, GonePeer{Peer: p, Since: now})
}

// DropGone forgets the removed server with key.
func (s *State) DropGone(key string) {
	s.Gone = slices.DeleteFunc(s.Gone, func(g GonePeer) bool { return g.Peer.PublicKey == key })
	if len(s.Gone) == 0 {
		s.Gone = nil
	}
}

// ExpireGone forgets removed servers told for longer than GoneKeep.
func (s *State) ExpireGone(now time.Time) {
	s.Gone = slices.DeleteFunc(s.Gone, func(g GonePeer) bool { return now.Sub(g.Since) > GoneKeep })
	if len(s.Gone) == 0 {
		s.Gone = nil
	}
}
