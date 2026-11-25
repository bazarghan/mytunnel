package version

import "testing"

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.8.16", "v0.8.15", true}, {"v0.10.0", "v0.9.9", true}, {"v0.8.15", "v0.8.15", false},
		{"v0.8.14", "v0.8.15", false}, {"dev", "v0.8.15", false}, {"v0.8.16", "dev", false},
		{"v1.0.0", "v0.9.0-spoof", true},
		{"v1.0.0", "v1.0.0-beta.1", true},
		{"v1.0.0-beta.1", "v1.0.0", false},
		{"v1.0.0-beta.10", "v1.0.0-beta.2", true},
		{"v1.0.0-rc.1", "v1.0.0-beta.9", true},
		{"v1.0.0-alpha", "v1.0.0-1", true},
		{"v1.0.0-1", "v1.0.0-alpha", false},
		{"v1.0.0-alpha.1", "v1.0.0-alpha", true},
		{"v1.0.0-beta.1", "v1.0.0-beta.1", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestRelease(t *testing.T) {
	for _, valid := range []string{"v1.0.0", "v0.9.0-spoof", "v1.0.0-beta.1", "v2.1.0-rc.2"} {
		if !Release(valid) {
			t.Errorf("Release(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{"", "dev", "1.0.0", "v1.0", "v1.0.0-", "v1.0.0; rm -rf /", "v1.0.0+build"} {
		if Release(invalid) {
			t.Errorf("Release(%q) = true, want false", invalid)
		}
	}
}
