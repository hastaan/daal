//go:build !unix

package provjournal

import "os"

// lockExclusive is a no-op where flock does not exist (Windows). The
// shell's is_locked is always false there too, so the two agree: the
// journal is still written, it just cannot say "a run is still going".
func lockExclusive(*os.File) error { return nil }
