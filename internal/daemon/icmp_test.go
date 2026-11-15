package daemon

import "testing"

func TestChecksum(t *testing.T) {
	// An echo request with id 1, seq 1 and no data: 0x0800 0000 0001 0001.
	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	if got := checksum(msg); got != 0xf7fd {
		t.Fatalf("checksum = %#04x, want 0xf7fd", got)
	}
	msg[2], msg[3] = 0xf7, 0xfd
	if got := checksum(msg); got != 0 {
		t.Fatalf("checksum over a sealed message = %#04x, want 0", got)
	}
	if got := checksum([]byte{1, 2, 3}); got != ^uint16(0x0102+0x0300) {
		t.Fatalf("odd length: %#04x", got)
	}
}
