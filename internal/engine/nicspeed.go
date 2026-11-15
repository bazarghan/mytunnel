package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// sysNet is where the kernel describes network interfaces (tests point it
// elsewhere).
var sysNet = "/sys/class/net"

// IfaceSpeed is the speed of the port interface name is plugged into, in
// Mbit/s, as its driver reports it: 1000 for a gigabit port, 10000 for 10
// gigabit. 0 when it isn't known: the link is down, or the card is a
// virtual one (virtio, which most VPSes have, rarely says), in which case
// driver names it. A bond reports the sum of its ports.
func IfaceSpeed(name string) (mbit int, driver string) {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return 0, ""
	}
	dir := filepath.Join(sysNet, name)
	if b, err := os.ReadFile(filepath.Join(dir, "speed")); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 && n < 10_000_000 {
			mbit = n
		}
	}
	if l, err := os.Readlink(filepath.Join(dir, "device", "driver")); err == nil {
		driver = filepath.Base(l)
	}
	return mbit, driver
}
