package engine

import "sync/atomic"

// Cronet availability, recorded rather than discarded.
//
// The naive tier is the only family whose dialability depends on a
// SECOND artifact shipping next to the engine: libcronet.so, which
// cannot be produced by tools/build-engine-android.sh (it needs
// cronet-go's Chromium toolchain) and is only copied in when a
// prebuilt one is found. So there are three ways to end up with an
// engine that cannot dial naive, and two of them are silent:
//
//  1. built with DAAL_NAIVE=0 → the outbound is not compiled in;
//  2. built with the tags but no libcronet.so for that ABI → the build
//     prints a warning to stderr and continues;
//  3. libcronet.so present but unloadable (wrong ABI, stripped).
//
// In all three the family table still grades `naive` MaturityStable
// and the UI draws it exactly like a vless-reality route, right up
// until connect fails. That is the same "confident claim backed by
// nothing" the Wave-1 honesty pass removed from five UI surfaces, so
// the loader now records its result instead of `_ =`-ing it.
//
// THREE states, not two, and the distinction matters: "we tried and it
// failed" is a fact worth telling the user, "we have not tried yet"
// is not. loadCronet runs when the driver starts, so before the first
// connect the honest answer is "unknown" — reporting `unsupported`
// there would be a fresh lie in the opposite direction.
var (
	cronetAttempted atomic.Bool
	cronetLoaded    atomic.Bool
)

// markCronet records the outcome of the one load attempt. Called by
// loadCronet in both build variants — including the no-naive variant,
// where "attempted, failed" is the correct description of an engine
// that has no naive outbound compiled in at all.
func markCronet(ok bool) {
	cronetLoaded.Store(ok)
	cronetAttempted.Store(true)
}

// CronetStatus reports whether the engine has tried to make the naive
// tier dialable, and whether it succeeded. Consumers must treat
// (false, _) as "unknown", never as "unsupported".
func CronetStatus() (attempted bool, ok bool) {
	return cronetAttempted.Load(), cronetLoaded.Load()
}

// cronetLibraryArg is the argument loadCronet hands cronet-go's
// LoadLibrary, which is a sync.Once: the FIRST call decides, for the
// life of the process, whether the naive tier can dial.
//
//   - Android: the bare soname. purego.Dlopen resolves it through the
//     app's linker namespace (jniLibs/<abi>/); cronet-go's own search
//     (executable directory, LD_LIBRARY_PATH, /usr/local/lib, /usr/lib)
//     never looks there.
//   - everywhere else: "" — cronet-go's own search, whose first stop is
//     the executable's directory, where a desktop build ships the
//     library. dlopen("libcronet.so") does NOT search that directory, so
//     the soname fails there and the Once caches the failure: the
//     library sits beside the binary and every naive route dies at
//     connect with "cannot open shared object file".
//
// Lives in this untagged file so the default test build covers it.
func cronetLibraryArg(goos string) string {
	if goos == "android" {
		return "libcronet.so"
	}
	return ""
}
