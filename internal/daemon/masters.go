package daemon

import (
	"context"
	"log"
	"strconv"
	"time"

	"neotunnel/internal/config"
	"neotunnel/internal/events"
	"neotunnel/internal/health"
)

// A main server that hasn't reached this node for ForgetDays (Iran's server
// reinstalled, sold, or gone) is forgotten with its tunnels, so they don't
// stay here for ever. Not while one of its tunnels still gets answers from
// the far end: that server is alive, only its control channel is cut.

const (
	checkMastersEvery = time.Hour
	// aliveWithin: a tunnel answered this recently means its far end runs.
	aliveWithin = time.Hour
)

func watchMasters(ctx context.Context, tracker *health.Tracker, reconcile func()) {
	t := time.NewTicker(checkMastersEvery)
	defer t.Stop()
	for {
		if forgetSilent(tracker.Snapshot(), time.Now()) {
			reconcile()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// forgetSilent forgets the masters silent too long whose tunnels don't
// answer either, and starts the count for masters from before it was kept.
// It reports whether anything was forgotten.
func forgetSilent(hs map[string]health.State, now time.Time) bool {
	st, err := config.Load()
	if err != nil || len(st.Masters()) == 0 {
		return false
	}
	start := false
	for _, m := range st.Masters() {
		start = start || m.LastContact.IsZero()
	}
	var gone []*config.Managed
	for _, m := range st.SilentMasters(now) {
		if !answering(st, m, hs, now) {
			gone = append(gone, m)
		}
	}
	if !start && len(gone) == 0 {
		return false
	}
	_, err = config.Update(func(st *config.State) error {
		for _, m := range st.Masters() {
			if m.LastContact.IsZero() {
				m.LastContact = now
			}
		}
		for _, m := range gone {
			st.ForgetMaster(m.Master.PublicKey)
		}
		return nil
	})
	if err != nil {
		log.Printf("forget silent main servers: %v", err)
		return false
	}
	for _, m := range gone {
		days := int(m.Silence(now).Hours() / 24)
		log.Printf("main server %s silent for %d days: forgot it and removed its %d tunnels", m.Master.Name, days, len(m.Tunnels))
		events.Add(events.Event{At: now.Unix(), Kind: events.Master, Auto: true, From: m.Master.Name,
			To: strconv.Itoa(len(m.Tunnels)), Detail: strconv.Itoa(days)})
	}
	return len(gone) > 0
}

// answering reports whether a tunnel of master m got an answer lately.
func answering(st *config.State, m *config.Managed, hs map[string]health.State, now time.Time) bool {
	ts, _ := st.Effective()
	for _, t := range ts {
		if t.MasterKey != m.Master.PublicKey {
			continue
		}
		if h, ok := hs[t.Name]; ok && h.Last > 0 && now.Sub(time.Unix(h.Last, 0)) < aliveWithin {
			return true
		}
	}
	return false
}
