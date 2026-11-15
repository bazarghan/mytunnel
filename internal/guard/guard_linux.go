package guard

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// Sockets lists the ports programs listen on (TCP listen, unconnected UDP),
// reachable from outside, with the program's name.
func Sockets() []Socket {
	type open struct {
		proto string
		s     ProcSocket
	}
	var socks []open
	inodes := map[uint64]bool{}
	for _, t := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		b, err := os.ReadFile(filepath.Join("/proc/net", t.file))
		if err != nil {
			continue
		}
		for _, s := range ParseProcNet(string(b)) {
			want := StateListen
			if t.proto == "udp" {
				want = StateUDPOpen
			}
			if s.State != want || !Reachable(s.Local.Addr()) || s.Local.Port() == 0 {
				continue
			}
			socks = append(socks, open{t.proto, s})
			inodes[s.Inode] = true
		}
	}
	// Only the listening sockets' owners are looked up: a busy server has
	// tens of thousands of connections, whose owners nobody needs.
	owners := socketOwners(inodes)
	seen := map[string]bool{}
	var out []Socket
	for _, o := range socks {
		sk := Socket{Proto: o.proto, Port: o.s.Local.Port(), Process: owners[o.s.Inode]}
		if seen[sk.Key()] {
			continue
		}
		seen[sk.Key()] = true
		out = append(out, sk)
	}
	return out
}

// socketOwners maps the socket inodes in want to the name of the process
// holding them, and stops looking once each has one.
func socketOwners(want map[uint64]bool) map[uint64]string {
	out := map[uint64]string{}
	if len(want) == 0 {
		return out
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if len(out) == len(want) {
			break
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64); err == nil && want[ino] {
				if _, ok := out[ino]; !ok {
					out[ino] = name
				}
			}
		}
	}
	return out
}

var sshdPort = regexp.MustCompile(`(?m)^port (\d+)$`)

// SSHPorts are the ports that must stay open for SSH: what sshd listens on
// and is configured for, the local port of every open SSH session, and 22.
func SSHPorts() []uint16 {
	ports := map[uint16]bool{22: true}
	var socks []ProcSocket
	inodes := map[uint64]bool{}
	for _, file := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(filepath.Join("/proc/net", file))
		if err != nil {
			continue
		}
		for _, s := range ParseProcNet(string(b)) {
			// An SSH session's local port is a listening port's (or a
			// port forwarded to one), so the sessions' sockets need no
			// owner lookup of their own unless no listener tells.
			if s.State == StateListen || (s.State == StateEstablished && s.Local.Port() < 32768) {
				socks = append(socks, s)
				inodes[s.Inode] = true
			}
		}
	}
	owners := socketOwners(inodes)
	for _, s := range socks {
		if owners[s.Inode] == "sshd" {
			ports[s.Local.Port()] = true
		}
	}
	for _, p := range sshdConfigPorts() {
		ports[p] = true
	}
	var list []uint16
	for p := range ports {
		list = append(list, p)
	}
	return list
}

var (
	sshdMu    sync.Mutex
	sshdAt    time.Time
	sshdPorts []uint16
)

// sshdConfigPorts are the ports sshd is configured for. sshd -T reads and
// checks the whole configuration, so its answer is kept for a minute.
func sshdConfigPorts() []uint16 {
	sshdMu.Lock()
	defer sshdMu.Unlock()
	if !sshdAt.IsZero() && time.Since(sshdAt) < time.Minute {
		return sshdPorts
	}
	sshdAt, sshdPorts = time.Now(), nil
	if out, err := exec.Command("sshd", "-T").Output(); err == nil {
		for _, m := range sshdPort.FindAllSubmatch(out, -1) {
			if n, err := strconv.Atoi(string(m[1])); err == nil && n > 0 && n < 65536 {
				sshdPorts = append(sshdPorts, uint16(n))
			}
		}
	}
	return sshdPorts
}

// PublicIfaces are the interfaces the guard filters by default: the one
// holding this server's address and those with a default route.
func PublicIfaces(address string) []string {
	set := map[string]bool{}
	if a, err := netip.ParseAddr(address); err == nil {
		if links, err := netlink.LinkList(); err == nil {
			for _, l := range links {
				as, _ := netlink.AddrList(l, netlink.FAMILY_ALL)
				for _, x := range as {
					if ip, ok := netip.AddrFromSlice(x.IP); ok && ip.Unmap() == a.Unmap() {
						set[l.Attrs().Name] = true
					}
				}
			}
		}
	}
	for _, dst := range []net.IP{net.IPv4(1, 1, 1, 1), net.ParseIP("2606:4700:4700::1111")} {
		if rs, err := netlink.RouteGet(dst); err == nil && len(rs) > 0 && rs[0].Gw != nil {
			if l, err := netlink.LinkByIndex(rs[0].LinkIndex); err == nil {
				set[l.Attrs().Name] = true
			}
		}
	}
	var out []string
	for n := range set {
		if !strings.HasPrefix(n, "nt-") && n != "lo" {
			out = append(out, n)
		}
	}
	return out
}

var (
	mu       sync.Mutex
	lastSet  string
	lastLoad time.Time
)

// refreshEvery reloads an unchanged ruleset now and then, to repair an
// external flush.
const refreshEvery = 5 * time.Minute

// Apply makes the guard's table match in (none when in has no interfaces).
func Apply(in Input) error {
	script := Script(in)
	mu.Lock()
	defer mu.Unlock()
	if script == lastSet && time.Since(lastLoad) < refreshEvery {
		return nil
	}
	if _, err := exec.LookPath("nft"); err != nil {
		if len(in.Ifaces) == 0 {
			return nil
		}
		return fmt.Errorf("the firewall needs nftables: apt install nftables")
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		lastSet = ""
		return fmt.Errorf("firewall: nft: %v: %s", err, strings.TrimSpace(out.String()))
	}
	lastSet, lastLoad = script, time.Now()
	return nil
}

// Remove deletes the guard's table.
func Remove() error { return Apply(Input{}) }

var droppedRe = regexp.MustCompile(`packets (\d+) bytes (\d+)`)

// Dropped is how many packets the guard has dropped since it was loaded.
func Dropped() (packets, bytes uint64) {
	out, err := exec.Command("nft", "list", "counter", "inet", Table, "dropped").Output()
	if err != nil {
		return 0, 0
	}
	if m := droppedRe.FindSubmatch(out); m != nil {
		packets, _ = strconv.ParseUint(string(m[1]), 10, 64)
		bytes, _ = strconv.ParseUint(string(m[2]), 10, 64)
	}
	return packets, bytes
}
