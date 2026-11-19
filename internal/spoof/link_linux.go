//go:build linux

package spoof

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"neotunnel/internal/config"
	"neotunnel/internal/mmsg"
	"neotunnel/internal/offload"
	"neotunnel/internal/sysctl"
	"neotunnel/internal/tun"
)

const (
	batch       = 64
	groBatch    = 16
	maxSegs     = 128
	maxDatagram = 9216 + CryptOverhead + 255 + 40
)

var useGRO = true

func openTUN(name string) (*os.File, bool, error) {
	if f, err := tun.OpenVnet(name); err == nil {
		if tun.SetOffload(f, true) == nil {
			return f, true, nil
		}
		f.Close()
	}
	f, err := tun.Open(name)
	return f, false, err
}

func keys(c Config) (send, recv []byte, err error) {
	if send, err = config.DeriveKey(c.Secret, c.Tunnel, fmt.Sprintf("spoof %d>%d", c.Side, 1-c.Side), 32); err != nil {
		return
	}
	recv, err = config.DeriveKey(c.Secret, c.Tunnel, fmt.Sprintf("spoof %d>%d", 1-c.Side, c.Side), 32)
	return
}

// attachTCPPortFilter attaches a 5-instruction classic BPF filter to a raw
// IPPROTO_TCP socket so the kernel only copies TCP segments with DstPort == port.
func attachTCPPortFilter(fd int, port uint16) {
	if port == 0 {
		return
	}
	filter := []unix.SockFilter{
		{Code: 0xb1, K: 0},                          // ldx 4*([0]&0xf)
		{Code: 0x48, K: 2},                          // ldh [x + 2] (TCP dport)
		{Code: 0x15, Jt: 0, Jf: 1, K: uint32(port)}, // jeq #port, +0, +1
		{Code: 0x06, K: 0xffff},                     // ret #65535
		{Code: 0x06, K: 0},                          // ret #0
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	_ = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
}

// relaxRPFilter disables strict reverse-path filtering so incoming packets
// carrying forged source IPs are not dropped by the kernel before reaching
// our socket.
func relaxRPFilter() {
	_ = sysctl.SetIface("all", "rp_filter", "0")
	_ = sysctl.SetIface("default", "rp_filter", "0")
}

// Link is a running Spoof tunnel end: a TUN interface, an outbound raw
// IP_HDRINCL socket, and an inbound UDP or raw protocol socket.
type Link struct {
	cfg     Config
	proto   string
	tun     *os.File
	vnet    bool
	sendFD  int
	recvFD  int
	udpConn *net.UDPConn
	r       *mmsg.Conn
	codec   *codec
	seq     atomic.Uint64
	sent    atomic.Int64
	done    chan struct{}
	wg      sync.WaitGroup

	BadPackets atomic.Uint64
}

// Start opens the TUN interface and raw/UDP sockets and starts moving packets.
func Start(c Config) (*Link, error) {
	if !c.Remote.Is4() {
		return nil, fmt.Errorf("spoof tunnel %s requires an IPv4 remote endpoint (got %s)", c.Name, c.Remote)
	}
	c.Proto = NormalizeProto(c.Proto)
	c.Dir = NormalizeDir(c.Dir)
	if c.Port == 0 && (c.Proto == ProtoUDP || c.Proto == ProtoTCP || c.Proto == ProtoICMP) {
		c.Port = 32443
	}
	if c.Key == 0 {
		c.Key = uint32(c.Port)<<16 | 0x4d4b
	}

	send, recv, err := keys(c)
	if err != nil {
		return nil, err
	}
	cd, err := newCodec(send, recv, c.Padding, c.NoCrypt)
	if err != nil {
		return nil, err
	}
	if c.AES && !c.NoCrypt {
		s, err1 := config.DeriveKey(c.Secret, c.Tunnel, fmt.Sprintf("spoof-aes %d>%d", c.Side, 1-c.Side), 32)
		r, err2 := config.DeriveKey(c.Secret, c.Tunnel, fmt.Sprintf("spoof-aes %d>%d", 1-c.Side, c.Side), 32)
		if err := errors.Join(err1, err2); err != nil {
			return nil, err
		}
		if err := cd.useAES(s, r); err != nil {
			return nil, err
		}
	}

	relaxRPFilter()

	// Outbound raw IPv4 socket with IP_HDRINCL.
	sendFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw send socket: %w", err)
	}
	if err := unix.SetsockoptInt(sendFD, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(sendFD)
		return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
	}
	_ = unix.SetsockoptInt(sendFD, unix.SOL_SOCKET, unix.SO_SNDBUF, mmsg.SocketBuffer)

	var (
		udpConn *net.UDPConn
		rd      *mmsg.Conn
		recvFD  = -1
	)
	if c.Proto == ProtoUDP {
		udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: int(c.Port)})
		if err != nil {
			unix.Close(sendFD)
			return nil, fmt.Errorf("listen on UDP %d: %w", c.Port, err)
		}
		mmsg.SetBuffers(udpConn, mmsg.SocketBuffer)
		rd, err = mmsg.New(udpConn, batch)
		if err != nil {
			udpConn.Close()
			unix.Close(sendFD)
			return nil, err
		}
	} else {
		ipProto := IPProto(c.Proto)
		recvFD, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, ipProto)
		if err != nil {
			unix.Close(sendFD)
			return nil, fmt.Errorf("open raw %s receive socket (proto %d): %w", c.Proto, ipProto, err)
		}
		_ = unix.SetsockoptInt(recvFD, unix.SOL_SOCKET, unix.SO_RCVBUF, mmsg.SocketBuffer)
		if c.Proto == ProtoTCP {
			attachTCPPortFilter(recvFD, c.Port)
		}
	}

	tf, vnet, err := openTUN(c.Name)
	if err != nil {
		if udpConn != nil {
			udpConn.Close()
		}
		if recvFD >= 0 {
			unix.Close(recvFD)
		}
		unix.Close(sendFD)
		return nil, err
	}

	l := &Link{
		cfg:     c,
		proto:   c.Proto,
		tun:     tf,
		vnet:    vnet,
		sendFD:  sendFD,
		recvFD:  recvFD,
		udpConn: udpConn,
		r:       rd,
		codec:   cd,
		done:    make(chan struct{}),
	}
	l.seq.Store(uint64(time.Now().UnixNano()))
	l.wg.Add(2)
	go l.outbound()
	if c.Proto == ProtoUDP {
		go l.inboundUDP()
	} else {
		go l.inboundRaw()
	}
	if c.Keepalive > 0 {
		l.wg.Add(1)
		go l.keepalive()
	}
	if c.PinholeInterval > 0 {
		if !c.Local.Unmap().Is4() {
			log.Printf("spoof %s: pinhole disabled (local endpoint %s is not IPv4)", c.Name, c.Local)
		} else if peerSrc, ok := peerExpectedOuterSrc(c); !ok {
			log.Printf("spoof %s: pinhole disabled (remote outer source %q is not predictable)", c.Name, c.SpoofSrc)
		} else {
			l.wg.Add(1)
			go l.pinhole(peerSrc.As4())
		}
	}
	return l, nil
}

// Close stops the link and closes its TUN interface and sockets.
func (l *Link) Close() {
	select {
	case <-l.done:
		return
	default:
	}
	close(l.done)
	l.tun.Close()
	if l.udpConn != nil {
		l.udpConn.Close()
	}
	if l.recvFD >= 0 {
		// Unblock Recvfrom by shutting down or closing the raw descriptor.
		_ = unix.Shutdown(l.recvFD, unix.SHUT_RDWR)
		unix.Close(l.recvFD)
	}
	if l.sendFD >= 0 {
		unix.Close(l.sendFD)
	}
	l.wg.Wait()
}

func (l *Link) closed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func (l *Link) emitRaw(frame []byte, rawBuf []byte) error {
	seq := l.seq.Add(1)
	src := resolveSpoofSrc(l.cfg, seq)
	dst := l.cfg.Remote.As4()
	pkt := buildOuterPacket(rawBuf, l.cfg, l.proto, src, dst, frame, seq)
	sa := &unix.SockaddrInet4{Port: int(l.cfg.Port), Addr: dst}
	return unix.Sendto(l.sendFD, pkt, 0, sa)
}

func (l *Link) emitPinhole(dst [4]byte, rawBuf []byte) error {
	seq := l.seq.Add(1)
	pkt := buildPinholePacket(rawBuf, l.cfg, l.proto, dst, seq)
	sa := &unix.SockaddrInet4{Port: int(portForSide(l.cfg.Port, 1-l.cfg.Side)), Addr: dst}
	return unix.Sendto(l.sendFD, pkt, 0, sa)
}

func (l *Link) sendControl(typ byte, payload []byte) {
	buf := make([]byte, l.codec.room(len(payload)))
	rawBuf := make([]byte, len(buf)+64)
	d := l.codec.seal(buf, typ, payload, uint32(time.Now().Unix()))
	if l.emitRaw(d, rawBuf) == nil {
		l.sent.Store(time.Now().UnixNano())
	}
}

func (l *Link) outbound() {
	defer l.wg.Done()
	buf := make([]byte, l.codec.room(65535))
	rawBuf := make([]byte, 65535+128)
	off := l.codec.overhead() - tagLen
	if l.cfg.NoCrypt {
		off = AuthOverhead
	}
	start := off
	if l.vnet {
		start -= offload.HdrLen
	}
	tailGuard := tagLen + l.codec.padding
	if l.cfg.NoCrypt {
		tailGuard = l.codec.padding
	}
	segs, sizes := make([][]byte, maxSegs), make([]int, maxSegs)
	for {
		n, err := l.tun.Read(buf[start : len(buf)-tailGuard])
		if err != nil {
			if !l.closed() && !errors.Is(err, os.ErrClosed) {
				log.Printf("spoof %s: read: %v", l.cfg.Name, err)
			}
			return
		}
		pkt := buf[off : start+n]
		ts := uint32(time.Now().Unix())
		if !l.vnet {
			d := l.codec.seal(buf, typeData, pkt, ts)
			if l.emitRaw(d, rawBuf) == nil {
				l.sent.Store(time.Now().UnixNano())
			}
			continue
		}
		h := offload.ParseHdr(buf[start:])
		if h.GSOType == offload.GSONone {
			if offload.Complete(pkt, h) != nil {
				continue
			}
			d := l.codec.seal(buf, typeData, pkt, ts)
			if l.emitRaw(d, rawBuf) == nil {
				l.sent.Store(time.Now().UnixNano())
			}
			continue
		}
		nseg, size := offload.Segments(pkt, h)
		if nseg == 0 || nseg > maxSegs {
			continue
		}
		for i := range segs[:nseg] {
			if len(segs[i]) < l.codec.room(size) {
				segs[i] = make([]byte, l.codec.room(size))
			}
		}
		k, err := offload.Segment(pkt, h, 0, segs, off, sizes)
		if err != nil {
			continue
		}
		sentOK := false
		for i := range k {
			d := l.codec.seal(segs[i], typeData, segs[i][off:off+sizes[i]], ts)
			if l.emitRaw(d, rawBuf) == nil {
				sentOK = true
			}
		}
		if sentOK {
			l.sent.Store(time.Now().UnixNano())
		}
	}
}

func (l *Link) inboundUDP() {
	defer l.wg.Done()
	n, size := batch, maxDatagram
	if useGRO && l.r.EnableGRO() {
		n, size = groBatch, 65535
	}
	bufs, sizes, from := make([][]byte, n), make([]int, n), make([]netip.AddrPort, n)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}
	off := nonceLen + headerLen
	if l.cfg.NoCrypt {
		off = AuthOverhead
	}
	var gro offload.Coalescer
	write := func(b []byte) error { l.tun.Write(b); return nil }
	for {
		k, err := l.r.Read(bufs, sizes, from)
		if err != nil {
			if !l.closed() {
				log.Printf("spoof %s: receive udp: %v", l.cfg.Name, err)
			}
			return
		}
		for i := range k {
			if sizes[i] < 0 {
				l.BadPackets.Add(1)
				continue
			}
			seg := l.r.Segment(i)
			if seg == 0 {
				seg = sizes[i]
			}
			for p := 0; p < sizes[i]; p += seg {
				d := bufs[i][p:min(p+seg, sizes[i])]
				typ, pkt, err := l.codec.open(d)
				if err != nil {
					l.BadPackets.Add(1)
					continue
				}
				if typ != typeData || len(pkt) == 0 {
					continue
				}
				if l.vnet && off >= offload.HdrLen {
					gro.Add(d[off-offload.HdrLen : off+len(pkt)])
				} else {
					l.tun.Write(pkt)
				}
			}
		}
		if l.vnet && off >= offload.HdrLen {
			gro.Flush(write)
		}
	}
}

func (l *Link) inboundRaw() {
	defer l.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, _, err := unix.Recvfrom(l.recvFD, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			if !l.closed() {
				log.Printf("spoof %s: receive raw (%s): %v", l.cfg.Name, l.proto, err)
			}
			return
		}
		if n <= 0 {
			continue
		}
		frame, ok := extractRawPayload(buf[:n], l.proto, l.cfg.Port, l.cfg.Key)
		if !ok || len(frame) == 0 {
			continue
		}
		typ, pkt, err := l.codec.open(frame)
		if err != nil {
			l.BadPackets.Add(1)
			continue
		}
		if typ != typeData || len(pkt) == 0 {
			continue
		}
		if l.vnet {
			var vbuf [maxDatagram]byte
			copy(vbuf[offload.HdrLen:], pkt)
			l.tun.Write(vbuf[:offload.HdrLen+len(pkt)])
		} else {
			l.tun.Write(pkt)
		}
	}
}

func (l *Link) keepalive() {
	defer l.wg.Done()
	l.sendControl(typeKeepalive, nil)
	t := time.NewTicker(l.cfg.Keepalive / 2)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-t.C:
			if time.Since(time.Unix(0, l.sent.Load())) >= l.cfg.Keepalive {
				l.sendControl(typeKeepalive, nil)
			}
		}
	}
}

func (l *Link) pinhole(dst [4]byte) {
	defer l.wg.Done()
	dport := effectivePort(l.cfg.Port)
	peerSport := portForSide(dport, 1-l.cfg.Side)
	dstAddr := netip.AddrFrom4(dst)
	if l.proto == ProtoUDP || l.proto == ProtoTCP {
		log.Printf("spoof %s: stateful pinhole active (%s %s:%d -> %s:%d every %s)", l.cfg.Name, l.proto, l.cfg.Local.Unmap(), dport, dstAddr, peerSport, l.cfg.PinholeInterval)
	} else {
		log.Printf("spoof %s: stateful pinhole active (%s %s -> %s every %s)", l.cfg.Name, l.proto, l.cfg.Local.Unmap(), dstAddr, l.cfg.PinholeInterval)
	}

	rawBuf := make([]byte, 64)
	if err := l.emitPinhole(dst, rawBuf); err != nil && !l.closed() {
		log.Printf("spoof %s: pinhole send: %v", l.cfg.Name, err)
	}

	burst := time.NewTimer(200 * time.Millisecond)
	select {
	case <-l.done:
		burst.Stop()
		return
	case <-burst.C:
	}
	if err := l.emitPinhole(dst, rawBuf); err != nil && !l.closed() {
		log.Printf("spoof %s: pinhole send: %v", l.cfg.Name, err)
	}

	t := time.NewTicker(l.cfg.PinholeInterval)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-t.C:
			if err := l.emitPinhole(dst, rawBuf); err != nil && !l.closed() {
				log.Printf("spoof %s: pinhole send: %v", l.cfg.Name, err)
			}
		}
	}
}

// Manager runs the Spoof links of the daemon.
type Manager struct {
	mu    sync.Mutex
	links map[string]*Link
}

func NewManager() *Manager { return &Manager{links: map[string]*Link{}} }

// Sync starts, restarts (when changed) and stops Spoof links to match cfgs.
func (m *Manager) Sync(cfgs []Config) []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	want := map[string]bool{}
	for _, c := range cfgs {
		want[c.Name] = true
		if cur, ok := m.links[c.Name]; ok {
			if cur.cfg == c {
				continue
			}
			cur.Close()
			delete(m.links, c.Name)
		}
		l, err := Start(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("tunnel %s: %w", c.Tunnel, err))
			continue
		}
		m.links[c.Name] = l
	}
	for name, l := range m.links {
		if !want[name] {
			l.Close()
			delete(m.links, name)
		}
	}
	return errs
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, l := range m.links {
		l.Close()
		delete(m.links, name)
	}
}
