//go:build linux

package spoof

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const probeMagic = "NTSPOOF1:"

func buildProbePayload(token, proto string) []byte {
	return []byte(probeMagic + token + ":" + NormalizeProto(proto))
}

func hasProbePayload(b []byte, token string) bool {
	return bytes.Contains(b, []byte(probeMagic+token+":"))
}

// ListenProbes listens across all 6 outer spoof protocols (udp, tcp, gre,
// ipip, sit, icmp) for probe packets carrying token until ctx or duration ends.
func ListenProbes(ctx context.Context, token string, port uint16, duration time.Duration) (map[string]bool, error) {
	if port == 0 {
		port = 32449
	}
	relaxRPFilter()
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	var (
		mu   sync.Mutex
		got  = map[string]bool{}
		wg   sync.WaitGroup
		mark = func(p string) {
			mu.Lock()
			got[p] = true
			mu.Unlock()
		}
	)

	// 1. UDP listener
	if uc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)}); err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer uc.Close()
			go func() {
				<-ctx.Done()
				uc.SetReadDeadline(time.Now())
			}()
			buf := make([]byte, 2048)
			for {
				n, _, err := uc.ReadFromUDP(buf)
				if err != nil {
					return
				}
				if hasProbePayload(buf[:n], token) {
					mark(ProtoUDP)
				}
			}
		}()
	}

	// 2. Raw protocol listeners (tcp, gre, ipip, sit, icmp)
	for _, proto := range []string{ProtoTCP, ProtoGRE, ProtoIPIP, ProtoSIT, ProtoICMP} {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, IPProto(proto))
		if err != nil {
			continue
		}
		if proto == ProtoTCP {
			attachTCPPortFilter(fd, port)
		}
		wg.Add(1)
		go func(p string, fd int) {
			defer wg.Done()
			defer unix.Close(fd)
			go func() {
				<-ctx.Done()
				_ = unix.Shutdown(fd, unix.SHUT_RDWR)
				unix.Close(fd)
			}()
			buf := make([]byte, 2048)
			for {
				n, _, err := unix.Recvfrom(fd, buf, 0)
				if err != nil {
					return
				}
				if n > 0 && hasProbePayload(buf[:n], token) {
					mark(p)
				}
			}
		}(proto, fd)
	}

	<-ctx.Done()
	wg.Wait()
	return got, nil
}

// SendProbes emits forged-source probe packets to remote across all requested
// outer protocols and returns which protocols the local kernel/NIC allowed
// sending without error.
func SendProbes(remote, local netip.Addr, port uint16, token, spoofSrc string, protos []string) (map[string]bool, error) {
	if !remote.Is4() {
		return nil, fmt.Errorf("remote %s must be an IPv4 address", remote)
	}
	if port == 0 {
		port = 32449
	}
	if len(protos) == 0 {
		protos = Protos()
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw send socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
	}

	cfg := Config{
		Tunnel:   "probe-" + token,
		Secret:   "spoof-probe-secret-" + token,
		Local:    local,
		Remote:   remote,
		Port:     port,
		Key:      uint32(port)<<16 | 0x4d4b,
		Dir:      DirBoth,
		SpoofSrc: spoofSrc,
		TTL:      64,
	}
	dst := remote.As4()
	sa := &unix.SockaddrInet4{Port: int(port), Addr: dst}
	sent := map[string]bool{}
	rawBuf := make([]byte, 512)

	for round := range 3 {
		for i, p := range protos {
			p = NormalizeProto(p)
			seq := uint64(round*16 + i + 1)
			src := resolveSpoofSrc(cfg, seq)
			payload := buildProbePayload(token, p)
			pkt := buildOuterPacket(rawBuf, cfg, p, src, dst, payload, seq)
			if err := unix.Sendto(fd, pkt, 0, sa); err == nil {
				sent[p] = true
			}
		}
		if round < 2 {
			time.Sleep(45 * time.Millisecond)
		}
	}
	return sent, nil
}
