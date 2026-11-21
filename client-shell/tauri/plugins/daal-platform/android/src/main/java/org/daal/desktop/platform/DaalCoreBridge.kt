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
 *   engine_set_tunnel_refresh(on)      ← DaalCoreBridge.setTunnelRefresh
 *   engine_scheduler_tick()            ← DaalCoreBridge.schedulerTick
 *   engine_route_precheck(routeId)     ← DaalCoreBridge.routePrecheck
 *   engine_connect_auto()              ← DaalCoreBridge.connectAuto
 *                                         (five fields of its answer)
 *   engine_network_facts(...)          ← DaalCoreBridge.networkFacts
 *                                         (engine_network_changed with
 *                                         the kind alone on an engine
 *                                         library without it)
 *   engine_export_diagnostics()        ← DaalCoreBridge.engineState
 *                                         (six fields of it)
 *   engine_field_probe_cancel(reason)  ← DaalCoreBridge.fieldProbeCancel
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
  /**
   * `engine_set_route`. BLOCKS until the engine has proved the route by
   * one real round trip through it, or given up: milliseconds on a good
   * route, about 8 s on a dead one, up to ~30 s on a link that is
   * crawling, minutes on a cold tor route. 0 = connected; -1 = refused,
   * failed, or cancelled by clearRoute.
   *
   * MUST NOT be called from the main thread (it froze the app and
   * raised an ANR on exactly the routes that do not work).
   * DaalVpnService calls it on its control thread.
   */
  external fun setRoute(routeId: String): Int

  /**
   * `engine_clear_route`. Safe from any thread and idempotent. It is
   * also the CANCEL of a setRoute in flight: the engine abandons its
   * connection check at once and the blocked setRoute returns -1.
   */
  external fun clearRoute(): Int

  /**
   * Point the engine's scheduled refresh at the engine's own loopback
   * SOCKS inlet (`true`), or clear it (`false`). Returns 0 on success,
   * -1 if there is no live inlet or the engine is not loaded.
   *
   * WHY THIS EXISTS. On Android the VpnService excludes our own package
   * from the TUN — it has to, or the engine's dial to the relay loops
   * back into its own tunnel — so a plain socket from this process does
   * NOT ride the tunnel. Since Wave 1 the engine refuses to fetch at all
   * in that situation rather than beaconing the user's real IP at a
   * distribution endpoint on a fixed cadence. That refusal is correct
   * and it is also why nothing scheduled currently reaches the network
   * while connected. This call is what lifts it: the engine's sing-box
   * config carries a loopback SOCKS5 inbound whose traffic goes to the
   * active outbound, and this hands the refresher a dialer that uses it.
   *
   * ORDERING — not optional. Call only AFTER setRoute has returned 0:
   * the engine publishes the inlet when the sing-box instance is up and
   * its inbounds are bound, so calling earlier returns -1. Call with
   * `false` BEFORE clearRoute on teardown, so the dialer is retracted
   * while the listener is still alive rather than after it dies.
   *
   * No endpoint and no credential cross this boundary. The inlet is
   * authenticated (loopback on Android is reachable by every other app
   * on the device) and the credential stays inside the engine.
   */
  external fun setTunnelRefresh(enabled: Boolean): Int

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
   * `engine_route_precheck`: would [setRoute] refuse this route right
   * now? Starts and stops nothing. Returns the engine's JSON —
   * `{"route_id", "refused": "" | code, "active_route"}` — or null when
   * the engine is not loaded or has no such call (the caller then just
   * attempts the route). A refusal is recorded in the engine's
   * diagnostics exactly as a refused setRoute records it. Safe from
   * any thread; does not block on a connection check.
   */
  external fun routePrecheck(routeId: String): String?

  /**
   * `engine_connect_auto`: the engine picks among every usable route,
   * tries them in order (the one that last worked on this network
   * first) and keeps the first that carries. BLOCKS for all of it — one
   * connection check per route tried — so, like [setRoute], it MUST
   * NOT be called from the main thread. [clearRoute] abandons it.
   *
   * Returns `{"connected": bool, "route_id": id | "", "verdict": code
   * | "", "tried": n, "candidates": n}`, or null when the engine is
   * not loaded, the call failed, or the engine has no such call. Ids,
   * closed codes and counts only; the list of routes tried stays in
   * the engine's diagnostics (`auto`), where the page reads it.
   *
   * Uses the TUN already handed over with [setTunFd], as setRoute
   * does. When a route is already connected it changes nothing and
   * names that route.
   */
  external fun connectAuto(): String?

  /**
   * What the phone knows about the network UNDER the tunnel, for the
   * engine: `engine_network_facts`. DaalVpnService calls it from its
   * ConnectivityManager callback (vpn/NetworkWatch.kt decides when), so
   * the engine learns of a change with the app in the background, has a
   * real per-network key for what it remembers, and can tell "this
   * phone has no internet" from "the server did not answer" without
   * sending anything.
   *
   * @param kind      "wifi" | "cellular" | "ethernet" | "other" | "none"
   * @param id        opaque per-network string ([org.daal.desktop.vpn.NetworkWatch.networkId]:
   *                  already a digest, no address in it); "" = none. The
   *                  engine hashes it again before it stores or logs
   *                  anything. Never log it on this side.
   * @param validated 1 the system reached the internet through this
   *                  network, 0 it did not, -1 not known
   * @param metered   1 / 0 / -1
   *
   * Returns 0 = the engine has the facts; 1 = this engine library has
   * no such call and was told the kind alone through
   * `engine_network_changed` (it then keeps its memory per KIND of
   * network, as before); 2 = that older engine has no word for these
   * facts ("none") and was told nothing; -1 = the engine is not loaded
   * or the call failed. Does not block on a connection check; must
   * still not be called from the main thread (it writes the engine's
   * store). Safe while [setRoute] / [connectAuto] is blocked on another
   * thread — the page has always called `engine_network_changed` that
   * way.
   */
  external fun networkFacts(kind: String, id: String, validated: Int, metered: Int): Int

  /**
   * The engine's own account of the connection, from its memory (not
   * the route store): `{"active_route": id | "" | null,
   * "route_running": bool | null, "route_check", "route_check_category",
   * "connect_refused", "connect_refused_route", "auto_mode": bool | null,
   * "auto_state", "auto_verdict"}`, or null when it
   * cannot be asked. Ids and closed codes only. DaalVpnService reads it
   * after a setRoute that did not return 0, to learn whether the route
   * that was connected before is still up.
   */
  external fun engineState(): String?

  /**
   * `engine_field_probe_cancel`: stop a network test that is running
   * (specs/field-probe-v2.md). [reason] is a closed code the result
   * keeps as its `abort_reason`: "vpn_active" when a VPN came up (see
   * FieldProbeWatch), "network_changed", "backgrounded", "connecting"
   * or "". The partial result is kept by the engine.
   *
   * Returns 1 = a test was running and is stopping, 0 = none was
   * running, -1 = the engine is not loaded, has no such call, or the
   * call failed. Does not block on the test; safe from any thread (not
   * needed on the main one).
   */
  external fun fieldProbeCancel(reason: String): Int

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
