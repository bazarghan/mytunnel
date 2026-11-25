package manage

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"hltunnel/internal/agent"
	"hltunnel/internal/config"
	"hltunnel/internal/engine"
	"hltunnel/internal/fleet"
	"hltunnel/internal/identity"
	"hltunnel/internal/service"
)

// The servers that manage this one, seen from here: what to do when one
// is gone and can't clean up after itself.

// MasterInfo is a main server of this node.
type MasterInfo struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Paired  bool   `json:"paired"`
	Tunnels int    `json:"tunnels"`
	// LastContact (unix s, 0 = not known yet) and the days since.
	LastContact int64 `json:"last_contact,omitempty"`
	SilentDays  int   `json:"silent_days"`
	// ForgetIn is the days left before it is forgotten for its silence (-1
	// = never: kept, or forgetting is off).
	ForgetIn int      `json:"forget_in"`
	Keep     bool     `json:"keep,omitempty"`
	Dropped  []string `json:"dropped,omitempty"`
}

// Masters lists this node's main servers.
func Masters(st *config.State, now time.Time) []MasterInfo {
	var out []MasterInfo
	days := st.ForgetDays()
	for _, m := range st.Masters() {
		mi := MasterInfo{Name: m.Master.Name, Address: m.Master.Address, Paired: m.EnrollToken == "",
			Tunnels: len(m.Tunnels), Keep: m.Keep, Dropped: m.Dropped, ForgetIn: -1}
		if !m.LastContact.IsZero() {
			mi.LastContact = m.LastContact.Unix()
			mi.SilentDays = int(m.Silence(now).Hours() / 24)
		}
		if days > 0 && !m.Keep {
			mi.ForgetIn = max(0, days-mi.SilentDays)
		}
		out = append(out, mi)
	}
	return out
}

// findMasters resolves "all", a master's name or its address.
func findMasters(st *config.State, which string) ([]*config.Managed, error) {
	var out []*config.Managed
	for _, m := range st.Masters() {
		host := m.Master.Address
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if which == "all" || m.Master.Name == which || host == which || m.Master.Address == which {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no main server %q here", which)
	}
	return out, nil
}

// ForgetMaster removes main servers ("all", a name or an address) from
// this node with everything they set up here. For a server that is gone
// for good; one that still runs adds this server again by pairing anew.
// It reports how many tunnels went.
func ForgetMaster(which string) (int, Change, error) {
	n := 0
	st, err := config.Update(func(s *config.State) error {
		ms, err := findMasters(s, which)
		if err != nil {
			return err
		}
		for _, m := range ms {
			n += len(m.Tunnels)
			s.ForgetMaster(m.Master.PublicKey)
		}
		return nil
	})
	if err != nil {
		return 0, Change{}, err
	}
	return n, applyHere(st), nil
}

// KeepMaster turns off (or back on) forgetting a silent main server.
func KeepMaster(which string, keep bool) error {
	_, err := config.Update(func(s *config.State) error {
		ms, err := findMasters(s, which)
		if err != nil {
			return err
		}
		for _, m := range ms {
			m.Keep = keep
		}
		return nil
	})
	return err
}

// SetForgetDays sets after how many silent days a main server is forgotten
// (0 = never).
func SetForgetDays(days int) error {
	if days < 0 || days > 3650 {
		return fmt.Errorf("days must be 0 (never) to 3650")
	}
	_, err := config.Update(func(s *config.State) error {
		s.ForgetMasterDays = days
		if days == 0 {
			s.ForgetMasterDays = -1
		}
		if days == config.DefaultForgetMasterDays {
			s.ForgetMasterDays = 0
		}
		return nil
	})
	return err
}

// DropManaged removes a main server's tunnel (by its name here) on this
// node only, with those over it, for when that server can't be reached to
// remove it. It stays off whatever the server sends until it restores the
// tunnel or deletes it itself. It reports the tunnels removed.
func DropManaged(name string) ([]string, Change, error) {
	var out []string
	st, err := config.Update(func(s *config.State) error {
		for _, m := range s.Masters() {
			for _, t := range s.ManagedTunnels(m.Master.PublicKey) {
				if t.Name == name {
					out = m.Drop(t.KeyName())
					return nil
				}
			}
		}
		if slices.ContainsFunc(s.Tunnels, func(t config.Tunnel) bool { return t.Name == name }) {
			return fmt.Errorf("tunnel %s is this server's own: remove it without --local", name)
		}
		return fmt.Errorf("no tunnel %q from a main server here", name)
	})
	if err != nil {
		return nil, Change{}, err
	}
	return out, applyHere(st), nil
}

// RestoreDropped lets tunnels removed by hand on a peer run there again
// (none = all of them).
func RestoreDropped(peer string, names []string) error {
	st, err := Node()
	if err != nil {
		return err
	}
	p, ok := st.Peer(peer)
	if !ok || !p.Paired() {
		return fmt.Errorf("unknown server %q", peer)
	}
	id, err := identity.LoadOrCreate()
	if err != nil {
		return err
	}
	c, err := agent.ToPeer(id, *p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Restore(ctx, names); err != nil {
		return err
	}
	_, err = fleet.Refresh(ctx, id, st, peer)
	return err
}

// applyHere applies a change made on this node alone.
func applyHere(st *config.State) Change {
	var ch Change
	for _, e := range engine.Apply(st).Errors {
		ch.Errors = append(ch.Errors, e.Error())
	}
	if !engine.InDaemon() {
		service.Reload()
	}
	return ch
}

// LeaveAll tells every paired peer to drop the tunnels this server set up
// there, for when this server goes away (uninstall). Those it can't reach
// get the command that does it there (Cleanup).
func LeaveAll() []Cleanup {
	st, err := Node()
	if err != nil {
		return nil
	}
	id, err := identity.LoadOrCreate()
	if err != nil {
		return nil
	}
	var (
		mu  sync.Mutex
		out []Cleanup
		wg  sync.WaitGroup
	)
	for _, p := range st.Peers {
		if !p.Paired() {
			continue
		}
		wg.Add(1)
		go func(p config.Peer) {
			defer wg.Done()
			err := fleet.Leave(context.Background(), id, p)
			mu.Lock()
			defer mu.Unlock()
			c := Cleanup{Peer: p.Name, Command: "hltunnel master forget " + st.Self}
			if err != nil {
				c.Error = err.Error()
			}
			out = append(out, c)
		}(p)
	}
	wg.Wait()
	slices.SortFunc(out, func(a, b Cleanup) int { return strings.Compare(a.Peer, b.Peer) })
	return out
}
