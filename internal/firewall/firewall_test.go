package firewall

import (
	"testing"
	"time"
)

// Asking ufw whether it is on runs a Python program: once per activeFor,
// not on every reconcile.
func TestActiveCached(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	now = func() time.Time { return clock }
	defer func() { now = time.Now; activeAt = time.Time{} }()
	activeAt = time.Time{}
	activeCached()
	first := activeAt
	clock = clock.Add(activeFor - time.Second)
	activeCached()
	if activeAt != first {
		t.Fatalf("ufw asked again after %v", activeFor-time.Second)
	}
	clock = clock.Add(2 * time.Second)
	activeCached()
	if activeAt == first {
		t.Fatalf("ufw not asked again after %v", activeFor+time.Second)
	}
}

// A rule ufw refused is reported on every call but only retried after
// retryFor.
func TestFailedRuleRetriedLater(t *testing.T) {
	clock := time.Unix(2_000_000, 0)
	now = func() time.Time { return clock }
	defer func() { now = time.Now; failed = map[string]failure{}; activeAt = time.Time{} }()
	key := "allow 9/udp"
	failed = map[string]failure{key: {at: clock, msg: "ufw " + key + ": refused"}}
	// ufw "on" without asking it.
	activeAt, activeOn = clock, true
	err := Ensure(Needs{UDPPorts: []int{9}})
	if err == nil || err.Error() != "ufw "+key+": refused" {
		t.Fatalf("Ensure = %v, want the earlier refusal", err)
	}
	if f := failed[key]; !f.at.Equal(clock) {
		t.Fatalf("rule retried before %v", retryFor)
	}
}
