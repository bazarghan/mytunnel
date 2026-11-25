// Package version is set at build time:
//
//	go build -ldflags "-X hltunnel/internal/version.Version=v1.0.0"
package version

import (
	"cmp"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Version is set by the build flags at release time (see cmd/hltunnel).
var Version = "v1.0.0"

const (
	Repo       = "bazarghan/mytunnel"
	RepoURL    = "https://github.com/" + Repo
	InstallURL = "https://raw.githubusercontent.com/" + Repo + "/main/install.sh"
)

func Arch() string { return runtime.GOARCH }

var tagRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

// Release reports whether v is a release tag ("v1.0.0", "v1.0.0-beta.1"), not a dev build.
func Release(v string) bool { return tagRe.MatchString(v) }

// Newer reports whether release a is newer than release b according to SemVer
// precedence ("v1.0.0" > "v0.9.0-spoof", "v1.0.0" > "v1.0.0-beta.1").
// A build that isn't a release ("dev") is never newer, nor older.
func Newer(a, b string) bool {
	pa, pb := tagRe.FindStringSubmatch(a), tagRe.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return cmpPre(pa[4], pb[4]) > 0
}

func cmpPre(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return 1
	}
	if b == "" {
		return -1
	}
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		if ap[i] == bp[i] {
			continue
		}
		da, db := isDigits(ap[i]), isDigits(bp[i])
		if da && db {
			return cmpDigits(ap[i], bp[i])
		}
		if da != db {
			if da {
				return -1
			}
			return 1
		}
		return cmp.Compare(ap[i], bp[i])
	}
	return cmp.Compare(len(ap), len(bp))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func cmpDigits(a, b string) int {
	ta, tb := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := cmp.Compare(len(ta), len(tb)); c != 0 {
		return c
	}
	return cmp.Compare(ta, tb)
}
