package manage

import (
	"fmt"
	"net"
	"net/netip"

	"hltunnel/internal/config"
	"hltunnel/internal/events"
	"hltunnel/internal/fleet"
)

// This server's public address lives in two places: State.Address, and this
// server's side of each of its tunnels, which is what the far end dials.
// Every change of the address moves both, applies the tunnels here and
// pushes them to the peers, which also learn where this server's agent is
// now. A new IP saved in Address alone left every peer's tunnel dialing the
// old one, while the control channel (the main server dials its peers)
// kept working.

// SetNode changes this node's name and/or public address. A new address is
// a change of the network like any other: it comes back with what landed
// here and on each peer.
func SetNode(name, address string) (Change, error) {
	if name != "" {
		if err := ValidNodeName(name); err != nil {
			return Change{}, err
		}
	}
	var to netip.Addr
	if address != "" {
		a, err := netip.ParseAddr(address)
		if err != nil {
			return Change{}, fmt.Errorf("address must be an IP: %w", err)
		}
		to = a.Unmap()
	}
	if name != "" {
		_, err := config.Update(func(s *config.State) error {
			if name != s.Self {
				if len(s.Tunnels) > 0 {
					return fmt.Errorf("remove tunnels before renaming this node")
				}
				s.Self = name
			}
			return nil
		})
		if err != nil {
			return Change{}, err
		}
	}
	if !to.IsValid() {
		return Change{}, nil
	}
	_, ch, err := moveAddress(to, localAddr(to))
	return ch, err
}

// moveAddress makes to this server's address everywhere (see
// config.MoveAddress) and records whether it is on one of this server's
// interfaces. Saving the address it already has still repairs tunnels
// that kept an old one. It returns the tunnels it moved.
func moveAddress(to netip.Addr, local bool) ([]string, Change, error) {
	st, err := config.Load()
	if err != nil {
		return nil, Change{}, err
	}
	if st.Address == to.String() && !st.StaleAddress() {
		if st.AddressLocal != local {
			_, err = config.Update(func(s *config.State) error {
				s.AddressLocal = local
				return nil
			})
		}
		return nil, Change{}, err
	}
	old := st.Address
	var moved []string
	_, ch, err := Commit(pairedPeers(st), func(s *config.State) error {
		moved = s.MoveAddress(to.String())
		s.AddressLocal = local
		return nil
	})
	if err != nil {
		return nil, ch, err
	}
	for _, n := range moved {
		events.Add(events.Event{Tunnel: n, Kind: events.Changed, Detail: "address " + old + " " + to.String()})
	}
	return moved, ch, nil
}

// pairedPeers are the peers a change of this server's address is pushed to:
// all of them, since each also keeps this server's address for its
// firewall, not only those its tunnels go to.
func pairedPeers(st *config.State) []string {
	var out []string
	for _, p := range st.Peers {
		if p.Paired() {
			out = append(out, p.Name)
		}
	}
	return out
}

// AddressWatch follows this server's public IP for the daemon: when the IP
// a provider gave the server changes (a new one for a filtered one, say),
// the tunnels move to the new IP by themselves. It only acts when the
// saved address was on the server's own interfaces (State.AddressLocal), is
// gone from them on two checks in a row, and the server's route to the
// internet now leaves from another public address. An address behind NAT,
// never on an interface, is the user's to change.
type AddressWatch struct {
	gone int // checks in a row the saved address was missing

	// local and detect stand in for the system in tests.
	local  func(netip.Addr) bool
	detect func(v6 bool) netip.Addr
}

// GoneChecks is how many checks in a row the address must be missing:
// once can be an interface coming back up.
const GoneChecks = 2

// Check runs once. It returns the address it moved to ("" = none), the
// tunnels moved, and how the change landed.
func (w *AddressWatch) Check() (string, []string, Change, error) {
	local, detect := w.local, w.detect
	if local == nil {
		local = localAddr
	}
	if detect == nil {
		detect = detectAddr
	}
	st, err := config.Load()
	if err != nil {
		return "", nil, Change{}, err
	}
	cur, err := netip.ParseAddr(st.Address)
	if err != nil {
		return "", nil, Change{}, nil
	}
	cur = cur.Unmap()
	if local(cur) {
		w.gone = 0
		moved, ch, err := moveAddress(cur, true)
		if len(moved) > 0 {
			return cur.String(), moved, ch, err
		}
		return "", nil, ch, err
	}
	if st.StaleAddress() {
		// Tunnels from before addresses moved with them.
		moved, ch, err := moveAddress(cur, st.AddressLocal)
		return cur.String(), moved, ch, err
	}
	if !st.AddressLocal {
		return "", nil, Change{}, nil
	}
	if w.gone++; w.gone < GoneChecks {
		return "", nil, Change{}, nil
	}
	to := detect(cur.Is6())
	if !to.IsValid() || to == cur || to.Is4() != cur.Is4() || !Public(to) || !local(to) {
		return "", nil, Change{}, nil
	}
	w.gone = 0
	moved, ch, err := moveAddress(to, true)
	return to.String(), moved, ch, err
}

// OtherAddress is the public IP this server's route to the internet leaves
// from when it isn't the saved address ("" = it is, or it's private: behind
// NAT the saved address is right). The panel offers it.
func OtherAddress(st *config.State) string {
	cur, _ := netip.ParseAddr(st.Address)
	to := detectAddr(cur.IsValid() && cur.Unmap().Is6())
	if !to.IsValid() || to == cur.Unmap() || !Public(to) {
		return ""
	}
	return to.String()
}

// Public reports whether a is an address the internet can reach: not
// private, shared (CGNAT), loopback or link-local.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// localAddr reports whether a is on one of this server's interfaces.
func localAddr(a netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, x := range addrs {
		if n, ok := x.(*net.IPNet); ok {
			if b, ok := netip.AddrFromSlice(n.IP); ok && b.Unmap() == a {
				return true
			}
		}
	}
	return false
}

// detectAddr is the source of this server's route to the internet.
func detectAddr(v6 bool) netip.Addr {
	target := ""
	if v6 {
		target = "2001:4860:4860::8888"
	}
	a, err := netip.ParseAddr(fleet.DetectAddress(target))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
