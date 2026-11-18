// Package neoexit finds NeoExit (free exits for AI services, a separate
// program) on this server and reads what it sees, so the panel can show
// it next to the server. NeoExit answers on a unix socket only root can
// open; NeoTunnel never changes anything there.
package neoexit

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

// SocketPath is where NeoExit's local API listens.
const SocketPath = "/run/neoexit/api.sock"

// Status is NeoExit's /v1/status. Fields are only ever added there, so
// this may be a subset.
type Status struct {
	Version  string    `json:"version"`
	Panel    string    `json:"panel"` // ":port/path/"; the server's address goes in front
	Proxy    string    `json:"proxy"`
	Services []Service `json:"services"`
	Exits    []Exit    `json:"exits"`
	LastRun  time.Time `json:"last_run"`
}

type Service struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"` // ok, geo, challenge, error, down
	Exit  string `json:"exit"`
}

type Exit struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Up      bool   `json:"up"`
	IP      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	Ms      int    `json:"ms,omitempty"`
}

var client = &http.Client{
	Timeout: 2 * time.Second,
	Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", SocketPath)
	}},
}

var (
	mu       sync.Mutex
	cached   *Status
	cachedAt time.Time
)

// Local is NeoExit on this server, or nil when it isn't installed or
// isn't running. Answers are kept for 10 seconds.
func Local() *Status {
	mu.Lock()
	defer mu.Unlock()
	if time.Since(cachedAt) < 10*time.Second {
		return cached
	}
	cachedAt = time.Now()
	cached = nil
	resp, err := client.Get("http://neoexit/v1/status")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var s Status
	if json.NewDecoder(resp.Body).Decode(&s) == nil {
		cached = &s
	}
	return cached
}

// What peers reported in their last status, kept in memory only (it
// changes every few minutes; the settings file shouldn't).
var (
	pmu   sync.Mutex
	peers = map[string]peerStatus{}
)

type peerStatus struct {
	s  *Status
	at time.Time
}

func SetPeer(name string, s *Status) {
	pmu.Lock()
	defer pmu.Unlock()
	peers[name] = peerStatus{s, time.Now()}
}

// Peer is what a peer last said about its NeoExit (nil: none, or the
// peer hasn't answered for 10 minutes).
func Peer(name string) *Status {
	pmu.Lock()
	defer pmu.Unlock()
	p, ok := peers[name]
	if !ok || time.Since(p.at) > 10*time.Minute {
		return nil
	}
	return p.s
}
