package fleet

import (
	"context"
	"log"
	"sync"
	"time"

	"hltunnel/internal/agent"
	"hltunnel/internal/config"
	"hltunnel/internal/identity"
)

// Leave tells a peer to forget this node and remove the tunnels it set up
// there. A peer that already did (it doesn't know us) counts as told.
func Leave(ctx context.Context, id *identity.Identity, p config.Peer) error {
	c, err := agent.ToPeer(id, p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, err = c.Leave(ctx)
	if agent.NotMaster(err) {
		return nil
	}
	return err
}

// TellGone tells the servers removed while they couldn't be reached to
// drop our tunnels, and forgets those told (or kept for GoneKeep).
func TellGone(ctx context.Context, id *identity.Identity) {
	st, err := config.Load()
	if err != nil || len(st.Gone) == 0 {
		return
	}
	now := time.Now()
	var (
		mu   sync.Mutex
		told []string
		wg   sync.WaitGroup
	)
	for _, g := range st.Gone {
		if now.Sub(g.Since) > config.GoneKeep {
			continue
		}
		wg.Add(1)
		go func(p config.Peer) {
			defer wg.Done()
			if Leave(ctx, id, p) == nil {
				log.Printf("removed server %s (%s) dropped this server's tunnels", p.Name, p.Address)
				mu.Lock()
				told = append(told, p.PublicKey)
				mu.Unlock()
			}
		}(g.Peer)
	}
	wg.Wait()
	config.Update(func(st *config.State) error {
		for _, k := range told {
			st.DropGone(k)
		}
		st.ExpireGone(now)
		return nil
	})
}
