package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// The health probes ping every tunnel's far end every few seconds. Running
// the ping program for each round cost a process start per tunnel per round,
// which was half of what the daemon spent at rest; the daemon sends the
// echo requests itself instead, on one raw ICMP socket per address family
// shared by every tunnel. Where such a socket can't be opened (not root),
// pingRound falls back to the program.

// pinger sends ICMP echo requests on one family and hands each reply to the
// request waiting for it.
type pinger struct {
	conn  *net.IPConn
	v6    bool
	id    uint16
	seq   atomic.Uint32
	mu    sync.Mutex
	waits map[uint16]waiter
}

type waiter struct {
	to netip.Addr
	ch chan time.Time
}

var (
	pingersMu sync.Mutex
	pingers   = map[bool]*pinger{}
	pingerErr = map[bool]error{}
)

// pingerFor is the shared pinger of a family, opened on first use. An
// error is remembered, so a host without raw sockets doesn't retry each
// round.
func pingerFor(v6 bool) (*pinger, error) {
	pingersMu.Lock()
	defer pingersMu.Unlock()
	if p := pingers[v6]; p != nil {
		return p, nil
	}
	if err := pingerErr[v6]; err != nil {
		return nil, err
	}
	network, laddr := "ip4:icmp", "0.0.0.0"
	if v6 {
		network, laddr = "ip6:ipv6-icmp", "::"
	}
	c, err := net.ListenPacket(network, laddr)
	if err != nil {
		pingerErr[v6] = err
		return nil, err
	}
	p := &pinger{conn: c.(*net.IPConn), v6: v6, id: uint16(os.Getpid()), waits: map[uint16]waiter{}}
	go p.read()
	pingers[v6] = p
	return p, nil
}

const (
	icmpEchoReply4   = 0
	icmpEchoRequest4 = 8
	icmpEchoRequest6 = 128
	icmpEchoReply6   = 129
)

// read hands replies to their waiters. Every ICMP message to this host
// reaches a raw socket; anything not an answer to us is skipped at once.
func (p *pinger) read() {
	buf := make([]byte, 1500)
	reply := byte(icmpEchoReply4)
	if p.v6 {
		reply = icmpEchoReply6
	}
	for {
		n, from, err := p.conn.ReadFromIP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		at := time.Now()
		if n < 8 || buf[0] != reply || binary.BigEndian.Uint16(buf[4:]) != p.id {
			continue
		}
		seq := binary.BigEndian.Uint16(buf[6:])
		src, _ := netip.AddrFromSlice(from.IP)
		p.mu.Lock()
		w, ok := p.waits[seq]
		if ok && w.to == src.Unmap() {
			delete(p.waits, seq)
		}
		p.mu.Unlock()
		if ok && w.to == src.Unmap() {
			w.ch <- at
		}
	}
}

// echo sends one request to addr and waits up to timeout for its reply.
func (p *pinger) echo(ctx context.Context, addr netip.Addr, timeout time.Duration) (time.Duration, bool) {
	seq := uint16(p.seq.Add(1))
	ch := make(chan time.Time, 1)
	p.mu.Lock()
	p.waits[seq] = waiter{to: addr, ch: ch}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waits, seq)
		p.mu.Unlock()
	}()
	msg := make([]byte, 8+16)
	msg[0] = icmpEchoRequest4
	if p.v6 {
		msg[0] = icmpEchoRequest6 // the kernel fills in the ICMPv6 checksum
	}
	binary.BigEndian.PutUint16(msg[4:], p.id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	copy(msg[8:], "hltunnel-health")
	if !p.v6 {
		binary.BigEndian.PutUint16(msg[2:], checksum(msg))
	}
	start := time.Now()
	if _, err := p.conn.WriteToIP(msg, &net.IPAddr{IP: addr.AsSlice()}); err != nil {
		return 0, false
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case at := <-ch:
		return at.Sub(start), true
	case <-t.C:
	case <-ctx.Done():
	}
	return 0, false
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// icmpRound is pingRound's round sent by the daemon itself: roundSize
// requests 0.2 s apart, each answered within a second. ok is false when
// no raw socket could be opened.
func icmpRound(ctx context.Context, a netip.Addr) (sent, got int, rtt time.Duration, ok bool) {
	p, err := pingerFor(a.Is6())
	if err != nil {
		return 0, 0, 0, false
	}
	type result struct {
		d  time.Duration
		ok bool
	}
	res := make(chan result, roundSize)
	for i := range roundSize {
		if i > 0 {
			select {
			case <-ctx.Done():
				return roundSize, got, 0, true
			case <-time.After(200 * time.Millisecond):
			}
		}
		go func() {
			d, ok := p.echo(ctx, a, time.Second)
			res <- result{d, ok}
		}()
	}
	var sum time.Duration
	for range roundSize {
		if r := <-res; r.ok {
			got++
			sum += r.d
		}
	}
	if got > 0 {
		rtt = sum / time.Duration(got)
	}
	return roundSize, got, rtt, true
}
