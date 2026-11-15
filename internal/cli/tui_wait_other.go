//go:build !unix

package cli

import "time"

// inputWithin reports whether more input arrives on fd within d; off Unix
// it can't tell, so a lone Esc is taken as Esc.
func inputWithin(int, time.Duration) bool { return false }
