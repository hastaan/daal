package selection

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSelectionPathHasNoNetwork enforces invariant 24 (Position B)
// across the FRP-3 selector tree: no Go file outside test files in
// core/internal/selection/ may reference net.Dial, net/http, or any
// http client/request constructor. The selector is a pure function
// of (probe results, RouteRow, netmem Snapshot, clock); it must
// never open a network connection of its own.
func TestSelectionPathHasNoNetwork(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file) // .../core/internal/selection
	bad := []string{
		`"net/http"`,
		`net.Dial(`,
		`net.DialTimeout(`,
		`http.Client`,
		`http.Get(`,
		`http.Post(`,
		`http.NewRequest`,
		`tls.Dial(`,
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stripped := stripGoComments(string(body))
		for _, b := range bad {
			if strings.Contains(stripped, b) {
				t.Errorf("%s contains forbidden token %q (Position B violation)", path, b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// stripGoComments removes line/block comments before scanning so a
// docstring like "selector does NOT use net/http" does not trip
// the test. Mirrors core/opsec_test.go::stripComments.
func stripGoComments(src string) string {
	var b strings.Builder
	inLineCmt := false
	inBlockCmt := false
	inString := false
	inRawString := false
	prev := byte(0)
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case inLineCmt:
			if c == '\n' {
				inLineCmt = false
				b.WriteByte(c)
			}
		case inBlockCmt:
			if prev == '*' && c == '/' {
				inBlockCmt = false
			}
		case inString:
			b.WriteByte(c)
			if c == '"' && prev != '\\' {
				inString = false
			}
		case inRawString:
			b.WriteByte(c)
			if c == '`' {
				inRawString = false
			}
		default:
			if c == '/' && i+1 < len(src) && src[i+1] == '/' {
				inLineCmt = true
				i++
				continue
			}
			if c == '/' && i+1 < len(src) && src[i+1] == '*' {
				inBlockCmt = true
				i++
				continue
			}
			if c == '"' {
				inString = true
				b.WriteByte(c)
				continue
			}
			if c == '`' {
				inRawString = true
				b.WriteByte(c)
				continue
			}
			b.WriteByte(c)
		}
		prev = c
	}
	return b.String()
}
