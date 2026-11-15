package daemon

import (
	"context"
	"log"
	"time"

	"neotunnel/internal/manage"
)

// addressEvery is how often the daemon checks this server's public IP (see
// manage.AddressWatch): a new IP reaches the tunnels within about a
// minute, two checks.
const addressEvery = 30 * time.Second

// watchAddress moves this server's tunnels to its new public IP when the
// IP changes, and pushes them to its peers.
func watchAddress(ctx context.Context) {
	var w manage.AddressWatch
	t := time.NewTicker(addressEvery)
	defer t.Stop()
	for {
		to, moved, ch, err := w.Check()
		switch {
		case err != nil:
			log.Printf("public address: %v", err)
		case to != "":
			log.Printf("public address is now %s: moved tunnels %v (%d error(s) here)", to, moved, len(ch.Errors))
			for _, p := range ch.Peers {
				if !p.OK {
					log.Printf("public address: %s didn't take it (%s); run its setup command there", p.Peer, p.Error)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
