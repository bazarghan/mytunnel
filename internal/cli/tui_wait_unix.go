//go:build unix

package cli

import (
	"time"

	"golang.org/x/sys/unix"
)

// inputWithin reports whether more input arrives on fd within d.
func inputWithin(fd int, d time.Duration) bool {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, int(d.Milliseconds()))
		if err == unix.EINTR {
			continue
		}
		return err == nil && n > 0
	}
}
