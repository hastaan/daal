// Host stubs for the naiveproxy headless-cronet static archive.
//
// The cronet component archive excludes a handful of android platform
// bridges (user-added CA roots, the pre-freeze memory trimmer, the
// power/thermal monitor) because in a normal Java-embedded Cronet those
// are provided by the app's Java layer. daal loads libcronet.so headless
// (no Java Cronet), so we provide safe no-op / default implementations.
// All of these are optional platform features a forward proxy never
// depends on. Return types are NOT part of the Itanium C++ mangling, so
// aliasing the value-returning members to a long/pointer-returning stub
// is ABI-safe.

#include <string>
#include <vector>

// naive pins the relay's self-signed leaf; it needs no user-added roots.
namespace net {
namespace android {
std::vector<std::string> GetUserAddedRoots() { return {}; }
}  // namespace android
}  // namespace net

extern "C" {
void daal_stub_void() {}
long daal_stub_ret0() { return 0; }
static char daal_pf_storage[1024] __attribute__((aligned(16)));
void* daal_stub_instance() { return daal_pf_storage; }
}

__asm__(
    ".globl _ZN4base7android32PreFreezeBackgroundMemoryTrimmer8InstanceEv\n"
    ".set _ZN4base7android32PreFreezeBackgroundMemoryTrimmer8InstanceEv, daal_stub_instance\n"
    ".globl _ZN4base7android32PreFreezeBackgroundMemoryTrimmer19ShouldUseModernTrimEv\n"
    ".set _ZN4base7android32PreFreezeBackgroundMemoryTrimmer19ShouldUseModernTrimEv, daal_stub_ret0\n"
    ".globl _ZN4base7android32PreFreezeBackgroundMemoryTrimmer36RegisterPrivateMemoryFootprintMetricEv\n"
    ".set _ZN4base7android32PreFreezeBackgroundMemoryTrimmer36RegisterPrivateMemoryFootprintMetricEv, daal_stub_void\n"
    ".globl _ZN4base7android32PreFreezeBackgroundMemoryTrimmer14BackgroundTask10CancelTaskEv\n"
    ".set _ZN4base7android32PreFreezeBackgroundMemoryTrimmer14BackgroundTask10CancelTaskEv, daal_stub_void\n"
    ".globl _ZN4base7android32PreFreezeBackgroundMemoryTrimmer25PostDelayedBackgroundTaskE13scoped_refptrINS_19SequencedTaskRunnerEERKNS_8LocationENS_12OnceCallbackIFvNS_26MemoryReductionTaskContextEEEENS_9TimeDeltaE\n"
    ".set _ZN4base7android32PreFreezeBackgroundMemoryTrimmer25PostDelayedBackgroundTaskE13scoped_refptrINS_19SequencedTaskRunnerEERKNS_8LocationENS_12OnceCallbackIFvNS_26MemoryReductionTaskContextEEEENS_9TimeDeltaE, daal_stub_void\n"
    ".globl _ZN4base7android32PreFreezeBackgroundMemoryTrimmer37PostDelayedBackgroundTaskModernHelperE13scoped_refptrINS_19SequencedTaskRunnerEERKNS_8LocationENS_12OnceCallbackIFvNS_26MemoryReductionTaskContextEEEENS_9TimeDeltaE\n"
    ".set _ZN4base7android32PreFreezeBackgroundMemoryTrimmer37PostDelayedBackgroundTaskModernHelperE13scoped_refptrINS_19SequencedTaskRunnerEERKNS_8LocationENS_12OnceCallbackIFvNS_26MemoryReductionTaskContextEEEENS_9TimeDeltaE, daal_stub_void\n"
    ".globl _ZNK4base24PowerMonitorDeviceSource21GetBatteryPowerStatusEv\n"
    ".set _ZNK4base24PowerMonitorDeviceSource21GetBatteryPowerStatusEv, daal_stub_ret0\n"
    ".globl _ZNK4base24PowerMonitorDeviceSource22GetCurrentThermalStateEv\n"
    ".set _ZNK4base24PowerMonitorDeviceSource22GetCurrentThermalStateEv, daal_stub_ret0\n");
