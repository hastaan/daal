//go:build !android || !cgo

package engine

// androidLog is a no-op off Android. See androidlog_android.go.
func androidLog(string) {}
