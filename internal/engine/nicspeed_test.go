package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIfaceSpeed(t *testing.T) {
	defer func(d string) { sysNet = d }(sysNet)
	sysNet = t.TempDir()
	card := func(name, speed string) {
		os.MkdirAll(filepath.Join(sysNet, name), 0o755)
		if speed != "" {
			os.WriteFile(filepath.Join(sysNet, name, "speed"), []byte(speed+"\n"), 0o644)
		}
	}
	card("eth0", "1000")
	card("ens3", "-1") // virtio: no speed
	card("down0", "")  // link down: reading fails
	card("bond0", "20000")
	for _, c := range []struct {
		name string
		want int
	}{{"eth0", 1000}, {"ens3", 0}, {"down0", 0}, {"bond0", 20000}, {"missing", 0}, {"", 0}, {"../eth0", 0}} {
		if got, _ := IfaceSpeed(c.name); got != c.want {
			t.Errorf("IfaceSpeed(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}
