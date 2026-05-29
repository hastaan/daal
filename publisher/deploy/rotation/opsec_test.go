package rotation

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRotationOpsec is the in-package backstop for invariant 22
// (Position B). The package-level publisher/deploy/opsec_test.go
// scans every .go file in the tree; this test pins the rotation/
// surface specifically.
//
// Forbidden: any direct net/http or net.Dial usage. The rotation
// package delegates ALL network I/O to provider.Provider, which is
// the documented network actor (Hetzner API). No other socket may
// be opened from this directory.
func TestRotationOpsec(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(file)

	forbidden := []string{
		`"net/http"`,
		`"net/rpc"`,
		`net.Dial(`,
		`net.DialTimeout(`,
		`http.Post(`,
		`http.PostForm(`,
		`http.Get(`,
		`tls.Dial(`,
		`os.Setenv(`, // rotation must not mutate process env
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stripped := stripGoComments(string(body))
		for _, tok := range forbidden {
			if strings.Contains(stripped, tok) {
				t.Errorf("%s: forbidden token %q (rotation/ delegates network I/O to provider.Provider)", path, tok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRotationNoAnalyticsImports asserts the rotation package
// imports nothing telemetry-shaped: no prometheus client, no
// expvar, no log/slog handlers wired to a network sink.
func TestRotationNoAnalyticsImports(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(file)

	forbidden := []string{
		`"github.com/prometheus/client_golang/prometheus"`,
		`"github.com/prometheus/client_golang/prometheus/promhttp"`,
		`"expvar"`,
		`"net/http/pprof"`,
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stripped := stripGoComments(string(body))
		for _, tok := range forbidden {
			if strings.Contains(stripped, tok) {
				t.Errorf("%s: forbidden analytics import %q", path, tok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// stripGoComments mirrors publisher/deploy/opsec_test.go's helper.
// Removes line + block comments before scanning so this docstring
// (which discusses net.Dial) doesn't trigger a false positive.
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
