package config

import "net/netip"

// MoveAddress makes now this server's public address: Address, and this
// server's side of every tunnel it owns whose underlay is of now's family.
// Each tunnel keeps the address its far end dials, so a new IP saved in
// Address alone left the peers dialing the old one. A side's source
// override (Local) moves too when it was the old address. It returns the
// tunnels it changed.
//
// Tunnels over another tunnel have no endpoint and need nothing; those over
// IPv6 keep theirs when now is IPv4, and the other way round.
func (s *State) MoveAddress(now string) []string {
	to, err := netip.ParseAddr(now)
	if err != nil {
		return nil
	}
	to = to.Unmap()
	old := s.Address
	s.Address = to.String()
	var moved []string
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		changed := false
		for j := range t.Sides {
			sd := &t.Sides[j]
			if sd.Node != s.Self || sd.Endpoint == "" {
				continue
			}
			ep, err := netip.ParseAddr(sd.Endpoint)
			if err != nil || ep.Unmap().Is4() != to.Is4() || ep.Unmap() == to {
				continue
			}
			sd.Endpoint = to.String()
			if sd.Local != "" && sd.Local == old {
				sd.Local = to.String()
			}
			changed = true
		}
		if changed {
			moved = append(moved, t.Name)
		}
	}
	return moved
}

// StaleAddress reports whether one of this server's own tunnels still names
// an address of Address's family other than Address for this server.
func (s *State) StaleAddress() bool {
	c := *s
	c.Tunnels = append([]Tunnel(nil), s.Tunnels...)
	return len(c.MoveAddress(s.Address)) > 0
}
