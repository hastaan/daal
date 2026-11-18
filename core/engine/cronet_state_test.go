package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The first LoadLibrary call is cached for the life of the process, so
// the name loadCronet passes decides whether naive can ever dial.
// Android must keep the soname (the app linker namespace is the only
// place the APK's library is visible); every other OS must use
// cronet-go's own search, which starts at the executable's directory —
// the soname is not searched there and its failure would be the cached
// answer. Found end to end on headless Linux: libcronet.so beside the binary,
// naive refused with "cannot open shared object file".
func TestCronetLibraryArg(t *testing.T) {
	if got := cronetLibraryArg("android"); got != "libcronet.so" {
		t.Errorf("android: got %q, want the soname (resolved via the app linker namespace)", got)
	}
	for _, goos := range []string{"linux", "darwin", "windows", "ios"} {
		if got := cronetLibraryArg(goos); got != "" {
			t.Errorf("%s: got %q, want \"\" (cronet-go's own search: executable dir first)", goos, got)
		}
	}
}

// TestCronetLibraryArg proves the helper; this proves the helper is what
// reaches cronet-go. loadCronet lives in a file gated on
// with_naive_outbound, which the default test build never compiles — so
// a later edit putting the literal soname back would leave the suite
// green and break naive off Android only. The source is parsed instead
// (build tags do not apply to the parser): every cronet LoadLibrary call
// in this package must pass exactly cronetLibraryArg(runtime.GOOS), and
// there must be one.
func TestLoadCronetUsesCronetLibraryArg(t *testing.T) {
	const cronetPath = "github.com/sagernet/cronet-go"
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	calls, refs := 0, 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		local := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == cronetPath {
				local = "cronet"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		if local == "" {
			continue
		}
		if local == "." || local == "_" {
			t.Errorf("%s: imports %s as %q; this test cannot follow its LoadLibrary calls", name, cronetPath, local)
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "LoadLibrary" {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != local {
				return true
			}
			refs++
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "LoadLibrary" {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != local {
				return true
			}
			calls++
			if len(call.Args) != 1 || !isCronetLibraryArgOfGOOS(call.Args[0]) {
				t.Errorf("%s: %s.LoadLibrary must be called with cronetLibraryArg(runtime.GOOS) — "+
					"the first call is cached for the process, and a literal soname is unloadable off Android",
					fset.Position(call.Pos()), local)
			}
			return true
		})
	}
	if calls < 1 {
		t.Fatal("no cronet LoadLibrary call in this package: loadCronet no longer pre-loads Cronet, so this test guards nothing")
	}
	// A reference that is not a direct call (a function value, an alias)
	// would carry an argument this test never sees.
	if refs != calls {
		t.Errorf("cronet LoadLibrary is referenced %d times but called directly %d times; call it directly", refs, calls)
	}
}

func isCronetLibraryArgOfGOOS(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "cronetLibraryArg" {
		return false
	}
	arg, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || arg.Sel.Name != "GOOS" {
		return false
	}
	pkg, ok := arg.X.(*ast.Ident)
	return ok && pkg.Name == "runtime"
}
