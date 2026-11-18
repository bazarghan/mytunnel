//go:build !linux

package spoof

import (
	"errors"
	"sync"
)

type Link struct{}

func Start(c Config) (*Link, error) {
	return nil, errors.New("spoof tunnels are only supported on Linux")
}

func (l *Link) Close() {}

type Manager struct {
	mu sync.Mutex
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Sync(cfgs []Config) []error {
	if len(cfgs) == 0 {
		return nil
	}
	return []error{errors.New("spoof tunnels are only supported on Linux")}
}

func (m *Manager) Close() {}
