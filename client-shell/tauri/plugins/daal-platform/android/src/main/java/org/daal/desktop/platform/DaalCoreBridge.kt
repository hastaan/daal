package org.daal.desktop.platform

/**
 * DaalCoreBridge is the only JNI surface between the Daal Android
 * platform plugin (Kotlin) and the in-process engine
 * (`libdaalcore.so`). Keeping JNI access in one object makes the
 * native-symbol contract explicit: anything the engine needs from the
 * host (set TUN fd, set route, protect-callback) lives here. Anything
 * the host needs from the engine (status, version) goes through the
 * Tauri command surface and not through JNI.
 *
 * The native methods are implemented by the Rust shim in
 * `daal-desktop-tauri_lib` (the cdylib loaded into the app process by
 * Tauri at startup), which in turn calls the libdaalcore.so ABI
 * symbols introduced by Phase 45:
 *
 *   engine_set_tun_fd(fd)              ← DaalCoreBridge.setTunFd
 *   engine_clear_tun_fd()              ← DaalCoreBridge.clearTunFd
 *   engine_register_protect_callback() ← DaalCoreBridge.registerProtectCallback
 *   engine_set_route(routeId)          ← DaalCoreBridge.setRoute
 *   engine_clear_route()               ← DaalCoreBridge.clearRoute
 *   engine_scheduler_tick()            ← DaalCoreBridge.schedulerTick
 *
 * The Phase 45 spec requires these JNI methods to be wired before the
 * first upstream dial; the VpnService respects that ordering.
 *
 * The protect callback is stored in a companion `currentProtect` field
 * so the Rust side can pull it via a JNI call when the engine driver
 * opens an upstream socket. We cannot pass a function pointer through
 * the JNI boundary directly; instead the Rust side calls back into
 * `DaalCoreBridge.invokeProtect(fd)` from a CGO `protect()` hook.
 */
object DaalCoreBridge {

  init {
    System.loadLibrary("daal_desktop_tauri_lib")
  }

  external fun setTunFd(fd: Int): Int
  external fun clearTunFd(): Int
  external fun registerProtectCallback(): Int
  external fun setRoute(routeId: String): Int
  external fun clearRoute(): Int

  /**
   * One `scheduler.Tick` at the engine's wall clock. Returns 0 on
   * success, -1 if the engine is not loaded/initialized or the tick
   * failed — never throws, so a timer pump can call it blind.
   *
   * This is what makes anything *scheduled* happen: subscription
   * refresh at each row's ProfileUpdateMin, revocation refresh,
   * bootstrap refresh, the hour-rollover budget reset, and the Phase 2G
   * burn-pressure auto-promotion into lifeline-strict. The engine gates
   * every one of those on a persisted "last good" stamp, so calling
   * this more often than needed is cheap and calling it late only costs
   * lateness — which is why the pump in DaalVpnService can be inexact.
   *
   * MUST NOT be called from the main thread: a tick that finds work due
   * dispatches network refreshes with 15 s timeouts inline.
   */
  external fun schedulerTick(): Int

  /**
   * Host-side protect implementation. Stored as a property so the
   * native side can fetch it (or so a unit test can stub it without
   * having to mock the JNI boundary). When the VpnService is the
   * active host, this points at `VpnService::protect`.
   */
  @Volatile
  var protectImpl: ((Int) -> Boolean)? = null

  /**
   * Invoked from native via JNI when the engine driver opens an
   * upstream socket. Returns true iff the host successfully excluded
   * the fd from the TUN.
   */
  @JvmStatic
  fun invokeProtect(fd: Int): Boolean {
    return protectImpl?.invoke(fd) ?: false
  }
}
