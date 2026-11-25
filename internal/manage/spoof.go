package manage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"hltunnel/internal/agent"
	"hltunnel/internal/config"
	"hltunnel/internal/engine"
	"hltunnel/internal/identity"
	"hltunnel/internal/spoof"
)

func randomProbeToken() string {
	var b [6]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// TestSpoof runs a bidirectional forged-source-IP path test across all 6 outer
// spoof protocols (udp, tcp, gre, ipip, sit, icmp) between this server and a
// paired peer.
func TestSpoof(ctx context.Context, id *identity.Identity, peerName, spoofSrc string) (spoof.ProbeReport, error) {
	st, err := Node()
	if err != nil {
		return spoof.ProbeReport{}, err
	}
	if err := spoof.ValidateSrc(spoofSrc); err != nil {
		return spoof.ProbeReport{}, err
	}
	p, ok := st.Peer(peerName)
	if !ok {
		return spoof.ProbeReport{}, fmt.Errorf("unknown server %q", peerName)
	}
	if !p.Paired() {
		return spoof.ProbeReport{}, fmt.Errorf("server %s is not paired yet; run its connect command on it first", p.Name)
	}
	rem, err := netip.ParseAddr(p.Address)
	if err != nil || !rem.Is4() {
		return spoof.ProbeReport{}, fmt.Errorf("server %s address %q must be IPv4 for Spoof test", p.Name, p.Address)
	}
	local, _ := engine.RouteSource(rem)
	if !local.Is4() {
		if a, err := netip.ParseAddr(st.Address); err == nil && a.Is4() {
			local = a
		}
	}
	c, err := agent.ToPeer(id, *p)
	if err != nil {
		return spoof.ProbeReport{}, err
	}
	port := FreePort(st, config.KindSpoof, p.Name)
	if port == 0 {
		port = 32449
	}

	rep := spoof.ProbeReport{
		Peer:     p.Name,
		Remote:   rem.String(),
		SpoofSrc: spoofSrc,
		Port:     port,
	}

	// 1. Outbound test (this server -> peer)
	tokOut := randomProbeToken()
	var (
		outGot  map[string]bool
		outErr  error
		outSent map[string]bool
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, err := c.SpoofProbe(ctx, agent.SpoofProbeRequest{
			Action: "listen",
			Token:  tokOut,
			Port:   port,
			Millis: 1600,
		})
		outGot, outErr = res.Protos, err
	}()
	time.Sleep(150 * time.Millisecond)
	outSent, _ = spoof.SendProbes(rem, local, port, tokOut, spoofSrc, spoof.Protos())
	wg.Wait()
	if errors.Is(outErr, agent.ErrUnsupported) {
		return rep, fmt.Errorf("%s runs an older version without Spoof probe support; update it first", p.Name)
	}
	if outErr != nil {
		return rep, outErr
	}
	for _, ok := range outSent {
		if ok {
			rep.OutEmitOK = true
			break
		}
	}

	// 2. Inbound test (peer -> this server)
	var (
		inGot  map[string]bool
		inSent map[string]bool
	)
	if local.Is4() {
		tokIn := randomProbeToken()
		wg.Add(1)
		go func() {
			defer wg.Done()
			inGot, _ = spoof.ListenProbes(ctx, tokIn, port, 1600*time.Millisecond)
		}()
		time.Sleep(150 * time.Millisecond)
		res, err := c.SpoofProbe(ctx, agent.SpoofProbeRequest{
			Action:   "send",
			Token:    tokIn,
			Port:     port,
			Remote:   local.String(),
			SpoofSrc: spoofSrc,
		})
		if err == nil {
			inSent = res.Protos
		}
		wg.Wait()
	}
	for _, ok := range inSent {
		if ok {
			rep.InEmitOK = true
			break
		}
	}

	var bothProtos, outProtos, inProtos []string
	for _, proto := range spoof.Protos() {
		r := spoof.ProbeProtoResult{
			Proto: proto,
			Title: spoof.ProtoTitle(proto),
			OutOK: outGot[proto],
			InOK:  inGot[proto],
		}
		rep.Protos = append(rep.Protos, r)
		if r.OutOK && r.InOK {
			bothProtos = append(bothProtos, strings.ToUpper(proto))
			if rep.RecommendedProto == "" {
				rep.RecommendedProto, rep.RecommendedDir = proto, spoof.DirBoth
			}
		} else if r.OutOK {
			outProtos = append(outProtos, strings.ToUpper(proto))
		} else if r.InOK {
			inProtos = append(inProtos, strings.ToUpper(proto))
		}
	}
	if rep.RecommendedProto == "" {
		for _, r := range rep.Protos {
			if r.OutOK {
				rep.RecommendedProto, rep.RecommendedDir = r.Proto, spoof.DirOut
				break
			}
		}
	}
	if rep.RecommendedProto == "" {
		for _, r := range rep.Protos {
			if r.InOK {
				rep.RecommendedProto, rep.RecommendedDir = r.Proto, spoof.DirIn
				break
			}
		}
	}

	switch {
	case len(bothProtos) > 0:
		rep.Summary = fmt.Sprintf("مسیر Spoof دوطرفه روی پروتکل‌های %s کاملاً باز است (پیشنهادی: حامل %s، جهت دوطرفه).", strings.Join(bothProtos, "، "), strings.ToUpper(rep.RecommendedProto))
	case len(outProtos) > 0:
		rep.Summary = fmt.Sprintf("ارسال Spoof از این سرور به %s روی %s باز است، اما دیتاسنتر سرور مقابل بسته‌های Spoof خروجی را مسدود می‌کند (پیشنهادی: حامل %s، جهت «فقط ارسال این سرور»).", p.Name, strings.Join(outProtos, "، "), strings.ToUpper(rep.RecommendedProto))
	case len(inProtos) > 0:
		rep.Summary = fmt.Sprintf("ارسال Spoof از %s به این سرور روی %s باز است، اما دیتاسنتر این سرور بسته‌های Spoof خروجی را مسدود می‌کند (پیشنهادی: حامل %s، جهت «فقط ارسال سرور مقابل»).", p.Name, strings.Join(inProtos, "، "), strings.ToUpper(rep.RecommendedProto))
	default:
		rep.Summary = "بسته‌های با IP مبدأ جعلی بین این دو سرور از فایروال دیتاسنتر (uRPF) عبور نکردند؛ از پروتکل‌های دیگر یا حامل واقعی استفاده کنید."
	}
	return rep, nil
}
