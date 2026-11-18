//go:build singbox && with_naive_outbound && with_purego

package engine

import (
	"runtime"

	cronet "github.com/sagernet/cronet-go"
)

// loadCronet loads the bundled libcronet.so before the naive outbound
// initializes. sing-box's naive outbound calls cronet.LoadLibrary("")
// lazily on first use, which on Android fails: cronet-go's findLibrary
// os.Stat-searches the executable dir + LD_LIBRARY_PATH, neither of which
// is the app's native-library dir. We pre-load by soname instead —
// purego.Dlopen("libcronet.so") resolves through Android's app linker
// namespace (jniLibs/<abi>/libcronet.so). LoadLibrary caches via sync.Once,
// so this must run BEFORE box.New builds the naive outbound; the later
// LoadLibrary("") then returns the cached success.
//
// A load failure is not fatal here: only the naive route needs Cronet, and
// it surfaces its own error at connect.
//
// Which name to load depends on the platform (cronetLibraryArg): the
// soname is right ONLY on Android. Everywhere else the library ships
// beside the binary, which dlopen() does not search — and because
// LoadLibrary is a sync.Once, a failed soname attempt here would be the
// cached answer for sing-box's own later LoadLibrary(""), the one call
// that WOULD have found it. So off Android we make that call ourselves.
//
// The result is RECORDED (see cronet_state.go) rather than discarded.
// It used to be `_ =`, which meant a build missing libcronet.so was
// indistinguishable at runtime from a working one — and the UI went on
// grading naive routes "stable" until the user pressed Connect.
func loadCronet() { markCronet(cronet.LoadLibrary(cronetLibraryArg(runtime.GOOS)) == nil) }
