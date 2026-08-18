package engine

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Tor binary discovery.
//
// The `tor` outbound is the ONLY family in Daal that needs a second
// EXECUTABLE — not a loadable library like naive's libcronet.so, but a
// process sing-box forks. sing-box 1.13.12's protocol/tor/outbound.go
// hands `executable_path` to github.com/cretz/bine, whose
// process.NewCreator wraps exec.CommandContext; there is no in-process
// tor. (bine ships a cgo-linked embedded tor under process/embedded,
// but sing-box never sets StartConf.ProcessCreator, so that path is
// unreachable from a config.)
//
// ANDROID. Since Android 10 an app may not execve a file it can write:
// files under the app's data directory carry the app_data_file SELinux
// label with no execute_no_trans permission. The one app-owned location
// that IS executable is the extracted native-library directory, so a
// binary must ship as jniLibs/<abi>/lib*.so and be exec'd from there.
// Daal already does exactly this for the publisher's daal-deploy CLI
// (tools/build-deploy-android.sh, and resolve_deploy_binary in
// client-shell/tauri/src-tauri/src/lib.rs), which is why this file can
// be written with confidence rather than hope: the pattern is shipping.
// It requires extractNativeLibs=true, which the app sets in
// client-shell/tauri/plugins/daal-platform/android/src/main/AndroidManifest.xml
// and re-asserts as jniLibs.useLegacyPackaging in app/build.gradle.kts.
//
// We locate that directory the same way the Rust shell does: by finding
// our own mapped path. Go can do better than /proc/self/maps parsing on
// the happy path — libdaalcore.so IS this code — but the map scan is
// the only method that works from a Go archive linked into someone
// else's .so, so it stays the fallback.
//
// NOTHING HERE DOWNLOADS ANYTHING. The binaries are build inputs, baked
// into the APK. See the packaging note at the bottom of this file.

// torBinaryNames maps a pluggable-transport name, as it appears at the
// head of a Tor bridge line, to the library-style filename its binary
// must carry inside the APK. The lib*.so naming is not cosmetic: the
// Android package manager only extracts files matching that pattern out
// of the APK's lib/<abi>/ directory.
//
// The empty key is tor itself, needed by every bridge including vanilla
// ones.
var torBinaryNames = map[string]string{
	"":          "libtor.so",
	"obfs4":     "liblyrebird.so", // lyrebird is the maintained obfs4proxy
	"meek_lite": "liblyrebird.so", // same binary, second PT method
	"webtunnel": "libwebtunnel.so",
	"snowflake": "libsnowflake.so",
}

// TorBinaryName returns the on-device filename for a pluggable
// transport, and whether Daal knows that transport at all. An unknown
// transport is a hard error at config time rather than a tor process
// that starts and then cannot dial: tor would log "Unable to find
// pluggable transport proxy" and sit in a bootstrap loop forever, which
// is precisely the hang this family must not have.
func TorBinaryName(pt string) (string, bool) {
	n, ok := torBinaryNames[strings.ToLower(pt)]
	return n, ok
}

var (
	torDirOnce sync.Once
	torDir     string
	torDirErr  error

	// torDirOverride lets the platform layer state the directory
	// outright. Set before the first resolution; used by tests and
	// available to a host that already knows the path.
	torDirMu       sync.Mutex
	torDirOverride string

	torStateDirMu sync.Mutex
	torStateDir   string
)

// SetTorBinaryDir overrides native-library discovery. Calling it with ""
// restores discovery.
func SetTorBinaryDir(dir string) {
	torDirMu.Lock()
	torDirOverride = dir
	torDirMu.Unlock()
	torDirOnce = sync.Once{}
}

// SetTorStateDir records the app-writable state directory. tor's
// data_directory is placed inside it. Called from abi.Init.
func SetTorStateDir(dir string) {
	torStateDirMu.Lock()
	torStateDir = dir
	torStateDirMu.Unlock()
}

// TorDataDirectory is the path handed to sing-box as `data_directory`.
//
// It is deliberately SHARED by every tor route. sing-box's own docs
// mark data_directory "Recommended" because "each start will be very
// slow if not specified" — that slowness is tor re-fetching the
// directory consensus. Daal restarts tor on every route switch (one
// bridge per route, by design), so a per-route data directory would pay
// a cold bootstrap every switch. Sharing is safe because Daal runs one
// route at a time; two concurrent tor instances would collide on tor's
// own lock file in this directory, and that constraint is worth naming
// out loud if route concurrency is ever added.
//
// It sits under the app state directory — writable, sandboxed, and NOT
// executable, which is fine because nothing here is exec'd.
func TorDataDirectory() (string, error) {
	torStateDirMu.Lock()
	sd := torStateDir
	torStateDirMu.Unlock()
	if sd == "" {
		return "", errors.New("engine: tor data directory unavailable: engine state directory not set")
	}
	return filepath.Join(sd, "tor"), nil
}

// TorBinaryDir returns the directory holding the tor and
// pluggable-transport executables.
func TorBinaryDir() (string, error) {
	torDirMu.Lock()
	ov := torDirOverride
	torDirMu.Unlock()
	if ov != "" {
		return ov, nil
	}
	torDirOnce.Do(func() { torDir, torDirErr = discoverTorBinaryDir() })
	return torDir, torDirErr
}

func discoverTorBinaryDir() (string, error) {
	if runtime.GOOS == "android" {
		if d, err := nativeLibraryDir(); err == nil {
			return d, nil
		} else {
			return "", err
		}
	}
	// Desktop: alongside the executable. An empty string is NOT an
	// error — it means "nothing is co-located", and TorBinaryPath then
	// looks on PATH.
	exe, err := os.Executable()
	if err != nil {
		return "", nil
	}
	return filepath.Dir(exe), nil
}

// desktopBinaryNames maps a pluggable transport to the plain executable
// name a desktop package manager installs, for the PATH fallback.
//
// REPAIR-PASS ADDITION, and the reason it is needed is a dead branch.
// TorBinaryPath used to document a fallback to "`tor` on PATH, which is
// the right answer on a Linux box where the user installed the distro
// tor package" — but that branch was guarded by `dir == ""`, and
// discoverTorBinaryDir returns filepath.Dir(exe) whenever
// os.Executable() succeeds, which on a desktop it does. So the branch
// was unreachable, and a Linux desktop with tor installed was told
// "the Tor executable is not installed: libtor.so missing from
// <exedir>" — looking for the ANDROID filename, in the wrong place, to
// report the wrong conclusion.
//
// The empty key is tor itself. The PT names are what Debian/Fedora and
// the upstream tarballs install; obfs4proxy is kept as an alias because
// lyrebird is its renamed continuation and older distros still ship the
// old name.
var desktopBinaryNames = map[string][]string{
	"":          {"tor"},
	"obfs4":     {"lyrebird", "obfs4proxy"},
	"meek_lite": {"lyrebird", "obfs4proxy"},
	"webtunnel": {"webtunnel-client"},
	"snowflake": {"snowflake-client"},
}

// nativeLibraryDir finds the app's extracted native-library directory by
// locating our own mapping in /proc/self/maps. libdaalcore.so is this
// code, so its directory is by definition the one the package manager
// extracted jniLibs into.
func nativeLibraryDir() (string, error) {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return "", fmt.Errorf("engine: cannot read /proc/self/maps: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		path := line[i+1:]
		if strings.HasSuffix(path, "/libdaalcore.so") {
			return filepath.Dir(path), nil
		}
	}
	return "", errors.New("engine: native library directory not found (libdaalcore.so absent from /proc/self/maps)")
}

// TorBinaryPath resolves the absolute path of one tor-family executable
// and verifies it is present. `pt` is "" for tor itself.
//
// The error text names the missing file and the directory searched.
// That is the whole point: the alternative failure mode is a tor process
// that never bootstraps, and a user staring at a spinner has no way to
// learn that a build did not include liblyrebird.so for their ABI.
func TorBinaryPath(pt string) (string, error) {
	name, known := TorBinaryName(pt)
	if !known {
		return "", fmt.Errorf("engine: unsupported Tor pluggable transport %q "+
			"(this build ships obfs4/meek_lite, webtunnel and snowflake)", pt)
	}
	dir, err := TorBinaryDir()
	if err != nil {
		return "", err
	}
	if dir == "" {
		// Desktop with no co-located binary. Only tor itself can be
		// left to PATH; a PT must be an absolute path because tor
		// execs it from a ClientTransportPlugin line.
		if pt == "" {
			return "", nil
		}
		return "", fmt.Errorf("engine: pluggable transport %q not found: no binary directory", pt)
	}
	p := filepath.Join(dir, name)
	st, err := os.Stat(p)
	if err != nil {
		// Desktop PATH fallback. On Android there is nothing to fall
		// back to — the only executable location is the extracted
		// native-library directory — so the error is final there.
		if runtime.GOOS != "android" {
			if found, ok := lookDesktopBinary(pt); ok {
				return found, nil
			}
		}
		what := "the Tor executable"
		if pt != "" {
			what = fmt.Sprintf("the %q pluggable transport", pt)
		}
		return "", fmt.Errorf("engine: %s is not installed: %s missing from %s, "+
			"and %s not found on PATH (this build was packaged without it)",
			what, name, dir, strings.Join(desktopBinaryNames[strings.ToLower(pt)], "/"))
	}
	if st.IsDir() {
		return "", fmt.Errorf("engine: %s is a directory, not an executable", p)
	}
	return p, nil
}

// lookDesktopBinary resolves a system-installed tor or pluggable
// transport on PATH. Returns the absolute path and true on success.
func lookDesktopBinary(pt string) (string, bool) {
	for _, n := range desktopBinaryNames[strings.ToLower(pt)] {
		if p, err := exec.LookPath(n); err == nil {
			return p, true
		}
	}
	return "", false
}

// PACKAGING REQUIREMENT — read before shipping a tor route.
//
// This file resolves paths. It cannot create binaries, and no code in
// Daal may fetch them at runtime: downloading executable code outside
// the store distribution channel violates Google Play's Device and
// Network Abuse policy and would also be a supply-chain hole. They are
// BUILD INPUTS. See docs/build-and-release.md.
//
// Required, per ABI in {arm64-v8a, armeabi-v7a, x86_64}, dropped into
// client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs/<abi>/:
//
//	libtor.so        tor daemon, PIE executable (ELF ET_DYN)
//	liblyrebird.so   obfs4 + meek_lite pluggable transport
//	libwebtunnel.so  webtunnel pluggable transport
//	libsnowflake.so  snowflake pluggable transport
//
// Each must be a position-independent EXECUTABLE, not a shared library:
// the same trick tools/build-deploy-android.sh already uses for
// libdaal_deploy.so (`go build -buildmode=pie`), where `file` reports
// "ELF 64-bit LSB pie executable ... interpreter /system/bin/linker64".
// The three pluggable transports are Go programs and build that way
// directly. tor is C and needs an NDK cross-compile against its
// dependencies.
