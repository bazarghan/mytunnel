package daemon

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

// The daemon's own echo requests, on both families (needs root, like the
// daemon: raw sockets).
func TestICMPRoundLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for raw ICMP sockets")
	}
	for _, a := range []string{"127.0.0.1", "::1"} {
		sent, got, rtt, ok := icmpRound(context.Background(), netip.MustParseAddr(a))
		if !ok {
			t.Fatalf("%s: no raw socket", a)
		}
		if sent != roundSize || got != roundSize || rtt <= 0 {
			t.Fatalf("%s: sent %d, got %d, rtt %v", a, sent, got, rtt)
		}
	}
	// Nobody answers here: the round is lost, not mistaken for another's.
	if _, got, _, _ := icmpRound(context.Background(), netip.MustParseAddr("192.0.2.123")); got != 0 {
		t.Fatalf("answers from an address nobody holds: %d", got)
	}
}
