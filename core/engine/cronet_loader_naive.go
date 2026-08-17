//go:build singbox && with_naive_outbound && with_purego

package engine

import cronet "github.com/sagernet/cronet-go"

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
// it surfaces its own error at connect. Cross-platform note: on
// desktop/linux the .so ships beside the binary so LoadLibrary("") already
// works, but the soname load is equally valid there.
//
// The result is RECORDED (see cronet_state.go) rather than discarded.
// It used to be `_ =`, which meant a build missing libcronet.so was
// indistinguishable at runtime from a working one — and the UI went on
// grading naive routes "stable" until the user pressed Connect.
func loadCronet() { markCronet(cronet.LoadLibrary("libcronet.so") == nil) }
