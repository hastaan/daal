// Host stubs for the naiveproxy headless-cronet static archive, and the
// identity string that says which archive a libcronet.so was linked from.
//
// The cronet component archive leaves a handful of android platform
// bridges undefined (user-added CA roots, the power/thermal monitor, and
// — in older archives — the pre-freeze memory trimmer) because in a
// normal Java-embedded Cronet those are provided by the app's Java
// layer. daal loads libcronet.so headless (no Java Cronet), so we provide
// safe no-op / default implementations. All of these are optional
// platform features a forward proxy never depends on. Return types are
// NOT part of the Itanium C++ mangling, so aliasing the value-returning
// members to a long/pointer-returning stub is ABI-safe.
//
// EVERY STUB IS WEAK. Which bridges the archive leaves out changes
// between cronet-go versions: the 2026-05 archive had no pre-freeze
// trimmer, the 2026-09 one carries the real one. A strong stub then
// collides with the real definition ("duplicate symbol") and the relink
// fails; a weak one simply loses to it. So a stub here is used only when
// the archive really has nothing, and build-libcronet-android.sh links
// with -z defs so a bridge that is missing from BOTH is a link error
// rather than a crash on the phone.

#include <string>
#include <vector>

// ---------------------------------------------------------------------
// Identity. build-libcronet-android.sh compiles this file with
//   -DDAAL_CRONET_LIB_ID="<go module>@<version> archive-sha256=<hex>"
// so the finished .so carries, in its own bytes, which libcronet.a it
// was linked from. tools/cronet/check-libcronet-stamp.sh reads it back.
// The sidecar stamp file can be copied next to any library; this cannot.
// Exported (and `used`) so neither the compiler nor --gc-sections can
// drop it.
#ifndef DAAL_CRONET_LIB_ID
#error "compile through tools/cronet/build-libcronet-android.sh (DAAL_CRONET_LIB_ID is not set)"
#endif
extern "C" __attribute__((visibility("default"), used))
const char daal_cronet_lib_id[] = "daal-cronet-lib-id: " DAAL_CRONET_LIB_ID "\n";

#define DAAL_WEAK __attribute__((weak, visibility("default")))

// naive pins the relay's self-signed leaf; it needs no user-added roots.
namespace net {
namespace android {
DAAL_WEAK std::vector<std::string> GetUserAddedRoots() { return {}; }
}  // namespace android
}  // namespace net

extern "C" {
void daal_stub_void() {}
long daal_stub_ret0() { return 0; }
static char daal_pf_storage[1024] __attribute__((aligned(16)));
void* daal_stub_instance() { return daal_pf_storage; }
}

#define DAAL_WEAK_ALIAS(sym, target) \
  __asm__(".weak " sym "\n.set " sym ", " target "\n")

DAAL_WEAK_ALIAS("_ZN4base7android32PreFreezeBackgroundMemoryTrimmer8InstanceEv", "daal_stub_instance");
DAAL_WEAK_ALIAS("_ZN4base7android32PreFreezeBackgroundMemoryTrimmer19ShouldUseModernTrimEv", "daal_stub_ret0");
DAAL_WEAK_ALIAS("_ZN4base7android32PreFreezeBackgroundMemoryTrimmer36RegisterPrivateMemoryFootprintMetricEv", "daal_stub_void");
DAAL_WEAK_ALIAS("_ZN4base7android32PreFreezeBackgroundMemoryTrimmer14BackgroundTask10CancelTaskEv", "daal_stub_void");
DAAL_WEAK_ALIAS("_ZN4base7android32PreFreezeBackgroundMemoryTrimmer25PostDelayedBackgroundTaskE13scoped_refptrINS_19SequencedTaskRunnerEERKNS_8LocationENS_12OnceCallbackIFvNS_26MemoryReductionTaskContextEEEENS_9TimeDeltaE", "daal_stub_void");
DAAL_WEAK_ALIAS("_ZN4base7android32PreFreezeBackgroundMemoryTrimmer37PostDelayedBackgroundTaskModernHelperE13scoped_refptrINS_19SequencedTaskRunnerEERKNS_8LocationENS_12OnceCallbackIFvNS_26MemoryReductionTaskContextEEEENS_9TimeDeltaE", "daal_stub_void");
DAAL_WEAK_ALIAS("_ZNK4base24PowerMonitorDeviceSource21GetBatteryPowerStatusEv", "daal_stub_ret0");
DAAL_WEAK_ALIAS("_ZNK4base24PowerMonitorDeviceSource22GetCurrentThermalStateEv", "daal_stub_ret0");
