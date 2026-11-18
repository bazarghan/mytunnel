//go:build !linux

package spoof

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

func ListenProbes(ctx context.Context, token string, port uint16, duration time.Duration) (map[string]bool, error) {
	return nil, errors.New("spoof probes are only supported on Linux")
}

func SendProbes(remote, local netip.Addr, port uint16, token, spoofSrc string, protos []string) (map[string]bool, error) {
	return nil, errors.New("spoof probes are only supported on Linux")
}
