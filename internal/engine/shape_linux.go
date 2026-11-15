package engine

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
)

// shapeHandle marks the qdisc as ours, so a limit the admin set by hand on
// a tunnel is never removed.
var shapeHandle = netlink.MakeHandle(0x7a7a, 0)

// queued remembers the smart queue last set per interface, since the netlink
// library can't read CAKE's settings back.
var (
	queuedMu sync.Mutex
	queued   = map[string]smart{}
)

// smart is a smart queue set on an interface: its rate and the root
// qdisc it put there ("cake", or "tbf" with fq_codel under it).
type smart struct {
	mbit int
	root string
}

// shape caps what an interface sends (mbit = 0: no cap) and, with queue > 0,
// runs a smart queue at that rate (Mbit/s): CAKE, or fq_codel under a token
// bucket on a kernel without it. Both ends shape their own side, which covers
// both directions.
//
// A smart queue a little under the path's real speed moves the queue from
// the path, where packets wait in large buffers, to here, where every flow
// gets its share and a ping waits behind no download: ping under load stays
// close to ping at rest.
func shape(name string, mbit, queue int) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	qs, err := netlink.QdiscList(l)
	if err != nil {
		return err
	}
	var cur netlink.Qdisc
	for _, q := range qs {
		if q.Attrs().Parent == netlink.HANDLE_ROOT && q.Attrs().Handle == shapeHandle {
			cur = q
		}
	}
	if queue > 0 && mbit > 0 {
		queue = min(queue, mbit)
	}
	queuedMu.Lock()
	last, had := queued[name]
	queuedMu.Unlock()
	if queue > 0 {
		// The fallback's root is a tbf too: what was put there tells it
		// from a plain limit, so neither is replaced on every reconcile.
		if cur != nil && had && last.mbit == queue && cur.Type() == last.root {
			return nil
		}
		root, err := smartQueue(name, queue)
		if err != nil {
			return err
		}
		queuedMu.Lock()
		queued[name] = smart{queue, root}
		queuedMu.Unlock()
		return nil
	}
	queuedMu.Lock()
	delete(queued, name)
	queuedMu.Unlock()
	if mbit <= 0 {
		if cur != nil {
			return netlink.QdiscDel(cur)
		}
		return nil
	}
	rate := uint64(mbit) * 125_000 // bytes per second
	if t, ok := cur.(*netlink.Tbf); ok && t.Rate == rate && !had {
		return nil
	}
	if cur != nil && cur.Type() != "tbf" {
		netlink.QdiscDel(cur) // a smart queue before; the bucket replaces it
	}
	// A burst of 10 ms at the rate (at least 32 KiB, so fast links still
	// fill), and up to 50 ms of queue before packets drop.
	burst := uint32(max(rate/100, 32<<10))
	return netlink.QdiscReplace(&netlink.Tbf{
		QdiscAttrs: netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: shapeHandle, Parent: netlink.HANDLE_ROOT},
		Rate:       rate,
		Buffer:     netlink.Xmittime(rate, burst),
		Limit:      uint32(rate/20) + burst,
	})
}

// smartQueue puts CAKE on the interface at mbit, or fq_codel under a token
// bucket where the kernel has no CAKE (the library can't build either).
func smartQueue(name string, mbit int) (string, error) {
	handle := "7a7a:"
	rate := strconv.Itoa(mbit) + "mbit"
	if err := tc("qdisc", "replace", "dev", name, "root", "handle", handle, "cake", "bandwidth", rate); err == nil {
		return "cake", nil
	}
	burst := strconv.Itoa(max(mbit*125_000/100, 32<<10))
	if err := tc("qdisc", "replace", "dev", name, "root", "handle", handle, "tbf", "rate", rate, "burst", burst, "latency", "20ms"); err != nil {
		return "", err
	}
	return "tbf", tc("qdisc", "replace", "dev", name, "parent", "7a7a:1", "fq_codel")
}

func tc(args ...string) error {
	out, err := exec.Command("tc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
