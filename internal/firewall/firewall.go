// Package firewall opens what HLTunnel needs when the host runs ufw. Without
// an active ufw it does nothing (nftables forwarding needs no extra rules).
package firewall

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Needs struct {
	Ifaces   []string // tunnel interfaces: traffic in and routed through them
	UDPPorts []int    // tunnel ports (FOU, VXLAN, GENEVE)
	Ports    []string // ufw port specs, e.g. "7710/tcp", "7711"
	ESP      bool     // encrypted tunnels: IPsec ESP packets
	// Peers are trusted addresses: our own servers, and the far ends of
	// tunnels that use a raw IP protocol (GRE, IPIP, SIT, L2TPv3), which ufw
	// has no rule for. Everything from them is allowed.
	Peers []string
}

func (n Needs) rules() [][]string {
	var out [][]string
	for _, i := range n.Ifaces {
		out = append(out,
			[]string{"allow", "in", "on", i},
			[]string{"route", "allow", "in", "on", i},
			[]string{"route", "allow", "out", "on", i})
	}
	for _, p := range n.UDPPorts {
		out = append(out, []string{"allow", strconv.Itoa(p) + "/udp"})
	}
	for _, p := range n.Ports {
		out = append(out, []string{"allow", p})
	}
	for _, p := range n.Peers {
		out = append(out, []string{"allow", "from", p})
	}
	if n.ESP {
		out = append(out, []string{"allow", "proto", "esp", "from", "any", "to", "any"})
	}
	return out
}

var (
	mu   sync.Mutex
	done = map[string]bool{} // rules already added by this process
	// failed holds rules ufw refused, with when and why, so a refusal is
	// retried now and then instead of on every reconcile.
	failed = map[string]failure{}
	// active caches whether ufw is on: ufw is a Python program, and asking
	// it on every reconcile of a server where it is installed but off (the
	// Ubuntu default) cost more than the rest of the reconcile.
	activeAt time.Time
	activeOn bool
)

type failure struct {
	at  time.Time
	msg string
}

// Rechecks: how long ufw's state and a refused rule are taken as they were.
const (
	activeFor = 2 * time.Minute
	retryFor  = 5 * time.Minute
)

// now is time.Now, replaced by tests.
var now = time.Now

func activeCached() bool {
	if t := now(); activeAt.IsZero() || t.Sub(activeAt) >= activeFor {
		activeOn, activeAt = Active(), t
	}
	return activeOn
}

// Active reports whether ufw is installed and enabled.
func Active() bool {
	if _, err := exec.LookPath("ufw"); err != nil {
		return false
	}
	out, err := exec.Command("ufw", "status").Output()
	return err == nil && strings.Contains(string(out), "Status: active")
}

// Ensure adds any missing ufw rules. Rules are added once per process; ufw
// itself skips rules that already exist.
func Ensure(n Needs) error {
	mu.Lock()
	defer mu.Unlock()
	var todo [][]string
	var bad []string
	t := now()
	for _, r := range n.rules() {
		key := strings.Join(r, " ")
		if done[key] {
			continue
		}
		if f, ok := failed[key]; ok && t.Sub(f.at) < retryFor {
			bad = append(bad, f.msg)
			continue
		}
		todo = append(todo, r)
	}
	if len(todo) == 0 && len(bad) == 0 {
		return nil
	}
	if !activeCached() {
		return nil
	}
	for _, r := range todo {
		key := strings.Join(r, " ")
		if out, err := exec.Command("ufw", r...).CombinedOutput(); err != nil {
			msg := fmt.Sprintf("ufw %s: %s", key, strings.TrimSpace(string(out)))
			failed[key] = failure{at: t, msg: msg}
			bad = append(bad, msg)
			continue
		}
		delete(failed, key)
		done[key] = true
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("%s", strings.Join(bad, "; "))
	}
	return nil
}
