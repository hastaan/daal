//go:build !android || !cgo

package engine

import (
	"fmt"
	"os"
	"sync"
)

var (
	stderrLogOnce sync.Once
	stderrLog     bool
)

// platformLog is a no-op off Android unless DAAL_ENGINE_LOG is set, in
// which case the (already scrubbed) line goes to stderr. See
// androidlog_android.go.
func platformLog(level int, msg string) {
	stderrLogOnce.Do(func() { stderrLog = os.Getenv("DAAL_ENGINE_LOG") != "" })
	if !stderrLog {
		return
	}
	tag := "I"
	if level == logLevelError {
		tag = "E"
	}
	fmt.Fprintf(os.Stderr, "daalengine %s %s\n", tag, msg)
}
