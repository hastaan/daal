package org.daal.desktop.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import org.daal.desktop.platform.DaalCoreBridge

/**
 * Phase 45 — Real `VpnService` lifecycle. Replaces the legacy stub
 * (which lived under `ai.daal.app.vpn`, leaked the fd by closing the
 * ParcelFileDescriptor after Builder.establish(), and used the wrong
 * DaalCoreBridge entry point).
 *
 * Lifecycle on `ACTION_START`:
 *   1. Promote to foreground with a low-importance "tunnel active"
 *      notification.
 *   2. Wire the protect callback into DaalCoreBridge BEFORE the
 *      engine has any chance to open an upstream socket.
 *   3. `Builder.establish()` the TUN inbound, detach the fd (the
 *      engine takes ownership; we must not close the
 *      ParcelFileDescriptor).
 *   4. Hand the fd to the engine via DaalCoreBridge.setTunFd.
 *   5. Call DaalCoreBridge.setRoute(routeId) — this is what triggers
 *      Start() on the in-process driver.
 *   6. DaalCoreBridge.setTunnelRefresh(true) — put the engine's own
 *      scheduled fetches on the tunnel via its loopback SOCKS inlet.
 *   7. Start the scheduler pump (see startSchedulerPump).
 *
 * On `ACTION_STOP` / `onRevoke` / `onDestroy`:
 *   1. stop the scheduler pump
 *   2. DaalCoreBridge.setTunnelRefresh(false)
 *   3. DaalCoreBridge.clearRoute()
 *   4. DaalCoreBridge.clearTunFd()  (engine closes the fd)
 *   5. stopForeground + stopSelf.
 *
 * Ordering matters, and every pair below has a failure behind it:
 * registerProtectCallback before setTunFd, setTunFd before setRoute,
 * setRoute before setTunnelRefresh(true) (the inlet is not bound until
 * the instance starts), setTunnelRefresh(false) before clearRoute (never
 * advertise a dialer for a listener that is going away), clearRoute
 * before clearTunFd.
 */
class DaalVpnService : VpnService() {

  /** Non-null exactly while the tunnel is up; see startSchedulerPump. */
  private var schedulerPump: ScheduledExecutorService? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_START -> {
        val routeId = intent.getStringExtra(EXTRA_ROUTE_ID)
        if (routeId.isNullOrEmpty()) {
          Log.w(TAG, "ACTION_START with no route_id; ignoring")
          stopSelf()
          return START_NOT_STICKY
        }
        if (!start(routeId)) {
          stopSelf()
          return START_NOT_STICKY
        }
        return START_STICKY
      }
      ACTION_STOP -> {
        teardown()
        stopSelf()
        return START_NOT_STICKY
      }
      else -> {
        // Restart after a system OOM kill: we don't have the route
        // id, so the safest behaviour is to stop and let the user
        // re-connect.
        stopSelf()
        return START_NOT_STICKY
      }
    }
  }

  override fun onRevoke() {
    teardown()
    super.onRevoke()
  }

  override fun onDestroy() {
    teardown()
    super.onDestroy()
  }

  private fun start(routeId: String): Boolean {
    promoteToForeground(routeId)

    // 1. Register the protect callback BEFORE the engine has any
    //    chance to open an upstream socket. The protect callback
    //    runs on the binder thread the JNI hop arrives on; calling
    //    VpnService.protect from there is fine per Android docs.
    DaalCoreBridge.protectImpl = { fd -> protect(fd) }
    DaalCoreBridge.registerProtectCallback()

    // 2. Establish the TUN inbound. We hold the ParcelFileDescriptor
    //    until the engine has accepted ownership so that on rejection
    //    we can close it cleanly (avoids a fd leak).
    //
    //    addDisallowedApplication(self) is what keeps the engine's own
    //    upstream sockets (sing-box outbounds to the relay) OUT of the
    //    TUN. On Android the VPN captures every app's traffic INCLUDING
    //    the VPN app's, so without this exclusion the engine's dial to
    //    the relay loops back into the TUN. The pure-Go alternatives —
    //    per-socket protect() bound to an auto-detected interface, or
    //    net.Interfaces()/sysfs enumeration — are unusable here: the
    //    untrusted-app SELinux domain denies netlink RTM_GETLINK,
    //    /proc/net/*, and /sys/class/net alike, so the engine can never
    //    learn an interface to bind to. Excluding our own package makes
    //    the exclusion at the routing layer, needs no interface list,
    //    and lets the engine dial normally (auto_detect_interface off).
    val builder = Builder()
      .setSession("Daal")
      .setMtu(1500)
      .addAddress("10.20.30.40", 32)
      .addRoute("0.0.0.0", 0)
      .addRoute("::", 0)
      .addDnsServer("1.1.1.1")
      .addDnsServer("9.9.9.9")
    try {
      builder.addDisallowedApplication(packageName)
    } catch (e: Throwable) {
      // NameNotFoundException is impossible for our own package, but a
      // failure here would silently loop traffic — fail the connect
      // loudly instead.
      Log.e(TAG, "addDisallowedApplication(self) failed: ${e.message}")
      DaalCoreBridge.protectImpl = null
      return false
    }
    val pfd: ParcelFileDescriptor = builder.establish()
      ?: run {
        Log.w(TAG, "VpnService.Builder.establish() returned null")
        DaalCoreBridge.protectImpl = null
        return false
      }

    // 3. Hand the fd to the engine. Use ParcelFileDescriptor.getFd()
    //    first so we can still close(pfd) if the engine rejects it;
    //    on success we detach so the engine owns the lifetime.
    val setRc = DaalCoreBridge.setTunFd(pfd.fd)
    if (setRc < 0) {
      Log.e(TAG, "engine_set_tun_fd returned $setRc; aborting")
      try { pfd.close() } catch (_: Throwable) {}
      DaalCoreBridge.protectImpl = null
      return false
    }
    // Engine accepted ownership; detach so close-on-pfd does not
    // touch the dup the engine is now using.
    pfd.detachFd()

    // 4. Activate the route → starts the driver.
    val routeRc = DaalCoreBridge.setRoute(routeId)
    if (routeRc < 0) {
      Log.e(TAG, "engine_set_route returned $routeRc; tearing down")
      DaalCoreBridge.clearTunFd()
      DaalCoreBridge.protectImpl = null
      return false
    }
    activeRouteId = routeId
    connected = true

    // 5. Put the engine's OWN fetches on the tunnel, before anything
    //    starts asking for them.
    //
    //    setRoute returning 0 means the in-process sing-box instance
    //    started, which means it has already bound every inbound in its
    //    config — including the loopback SOCKS5 refresh inlet. Only then
    //    does the engine publish that inlet, and only then does this
    //    call succeed. So the listener provably exists before the
    //    refresher is ever handed a dialer that points at it; there is
    //    no window in which a due refresh dials a dead port.
    //
    //    A failure here is NOT fatal to the connection: the tunnel works
    //    either way, and the engine's fetches stay fail-closed
    //    (refresh.ErrTunnelRequired) rather than falling back to a
    //    direct dial from the user's real address. Losing scheduled
    //    refresh is a degradation; leaking the address is not one we
    //    take. Log it and carry on.
    val refreshRc = try {
      DaalCoreBridge.setTunnelRefresh(true)
    } catch (e: Throwable) {
      Log.e(TAG, "engine_set_tunnel_refresh threw: ${e.message}")
      -1
    }
    if (refreshRc < 0) {
      Log.w(
        TAG,
        "engine_set_tunnel_refresh returned $refreshRc; scheduled refresh " +
          "stays disabled for this session (fail-closed, not direct-dial)",
      )
    }

    // 6. Now start ticking. The pump comes last on purpose: a tick that
    //    finds work due dispatches refreshes inline, and step 5 is what
    //    decides whether those can go anywhere at all.
    startSchedulerPump()
    return true
  }

  private fun teardown() {
    if (!connected) return
    connected = false
    stopSchedulerPump()
    // Retract the tunnel dialer BEFORE the route (and with it the
    // loopback inlet) goes away, so no in-flight or newly-started fetch
    // can be handed a dialer pointing at a listener that is already
    // closing. The engine clears the same state itself when the driver
    // stops — this is belt and braces, and it makes the ordering
    // readable from the host side, which is where the mistake would be
    // made.
    try { DaalCoreBridge.setTunnelRefresh(false) } catch (_: Throwable) {}
    try { DaalCoreBridge.clearRoute() } catch (_: Throwable) {}
    try { DaalCoreBridge.clearTunFd() } catch (_: Throwable) {}
    DaalCoreBridge.protectImpl = null
    activeRouteId = null
    stopForeground(STOP_FOREGROUND_REMOVE)
  }

  /**
   * The mobile scheduler pump.
   *
   * The engine's scheduler is host-driven: nothing inside libdaalcore
   * calls scheduler.Tick on its own, so subscription refresh,
   * revocation refresh, bootstrap refresh, the hour-rollover budget
   * reset and burn-pressure auto-promotion into lifeline-strict all
   * happen exactly as often as some host asks for them. Desktop has
   * driven a 60 s thread since D-2.1 (src-tauri/src/lib.rs). Android
   * had no driver it could rely on, so on the one platform where all
   * four transports are field-proven, nothing scheduled ever fired
   * with any dependability.
   *
   * MECHANISM CHOSEN: a single-thread ScheduledExecutorService owned by
   * this foreground service, at a fixed *delay* of 60 s, plus one
   * immediate tick at tunnel-up. Rationale, against the four things
   * that actually decide this on Android:
   *
   *  - Backgrounded. A bare thread in the activity's process — which is
   *    what the Tauri shell's setup() thread is, and it runs here too —
   *    stops being scheduled the moment the process is cached: since
   *    Android 12 the cached-app freezer SIGSTOPs cached processes, and
   *    the LMK reclaims them first. Tying the pump to the foreground
   *    service instead means it runs exactly while the process is
   *    exempt from both. This is the whole reason the desktop pattern
   *    could not simply be copied.
   *
   *  - Doze. Doze defers alarms, jobs and network for *idle apps*; it
   *    does not suspend the threads of a process hosting a foreground
   *    service. So the pump keeps firing with the screen off, which is
   *    when a refresh is cheapest and when burn-pressure most needs to
   *    be able to promote without a human present. We hold no wakelock
   *    of our own: if the SoC suspends, ticks simply land late, and
   *    late is fine — every action is cadence-gated on a persisted
   *    stamp, so a tick is a no-op unless something is genuinely due.
   *
   *  - Battery. A tick with nothing due is a handful of SQLite reads on
   *    an already-open database and zero packets, on a process that is
   *    already awake running a VPN tunnel. The tunnel dominates by
   *    orders of magnitude. Fixed *delay* (not fixed rate) so a slow
   *    tick can never produce a catch-up burst.
   *
   *  - Tunnel down. The pump deliberately does not run, and the reason
   *    is battery/uselessness plus the fingerprint note below — not a
   *    claim that ticking with the tunnel UP is leak-free. The
   *    tunnel-down window is covered instead by (a) the Tauri shell's
   *    60 s thread, which lives in THIS SAME PROCESS (the service has
   *    no android:process attribute) and so keeps running whenever the
   *    process is alive, and (b) the immediate tick at tunnel-up.
   *
   * REFRESH EGRESS — WHERE A TICK'S PACKETS ACTUALLY GO.
   *
   * start() calls builder.addDisallowedApplication(packageName), which
   * by design keeps every socket owned by this app's UID — including
   * the Go engine's — OUT of the TUN. That exclusion is load-bearing:
   * without it the engine's dial to the relay loops back into its own
   * tunnel. It also means a plain socket from this process does not
   * ride the tunnel, so for a long time a due subscription / revocation
   * / bootstrap refresh was fetched over the censored network from the
   * user's real IP while the UI said "connected". Wave 1 stopped that
   * by refusing the fetch outright (refresh.ErrTunnelRequired) — never
   * by dialling direct — which left everything scheduled inert while
   * connected.
   *
   * Wave 2 restores the capability instead of the leak: the engine's
   * generated sing-box config now carries a loopback SOCKS5 inbound
   * whose traffic route.final sends to the active outbound, and start()
   * calls DaalCoreBridge.setTunnelRefresh(true) — AFTER setRoute
   * succeeds, so the listener is provably bound first — which installs
   * a tunnel-aware dialer inside the engine. A tick's refreshes then
   * leave the device over the relay and the audit records
   * `via_tunnel:true`.
   *
   * All THREE scheduled kinds are covered, which took two goes to get
   * right: subscription and revocation read the dialer through
   * refresh.Refresher, and bootstrap through abi.bootstrapDialer, which
   * until the Wave 2 repair pass returned a direct dialer
   * unconditionally — so KindBootstrap kept egressing in the clear on
   * its 24 h cadence, from this very pump, for a whole wave. If you add
   * a fourth kind, make its dialer ask refresh.TunnelRequired() too.
   *
   * Two properties to preserve when adding to the tick:
   *   1. If setTunnelRefresh failed (logged, non-fatal), the engine is
   *      still fail-closed, NOT direct-dialling. A tick is then a
   *      no-op for anything network-shaped. Do not "helpfully" add a
   *      direct-dial fallback anywhere.
   *   2. The pump starts after step 5 and stops before the dialer is
   *      retracted in teardown(). Keep that order.
   *
   * REJECTED:
   *
   *  - WorkManager / JobScheduler periodic work. The right tool for
   *    "run every 15 minutes even if the app is dead" — but the engine
   *    is loaded and initialized by the Tauri activity's run(), so in a
   *    worker-only process start the JNI bridge has no engine and the
   *    tick is a guaranteed no-op. It would need a headless engine-init
   *    path first (worth doing; it is not Wave 1), and it would add an
   *    androidx.work dependency to a module that has three. It would
   *    also put periodic un-tunnelled network on a fixed cadence, which
   *    is the fingerprint objection above with a scheduler attached.
   *
   *  - AlarmManager setExactAndAllowWhileIdle. Needs SCHEDULE_EXACT_ALARM
   *    / USE_EXACT_ALARM on Android 12+ — a user-visible, Play-scrutinised
   *    permission on an app whose whole posture is to look boring — and
   *    it wakes the device out of Doze to buy precision the scheduler
   *    does not want.
   *
   *  - Tick-on-resume only. Fires exactly when the user is looking at
   *    the app, which is when the manual refresh button already works,
   *    and never when they are not — leaving background auto-promotion,
   *    the one behaviour that exists to act without the user, unable to
   *    act without the user.
   *
   * TRADE-OFF ACCEPTED: with the app killed and the tunnel down,
   * nothing ticks until the user opens the app or connects. Closing
   * that needs headless engine init, not a different timer.
   */
  private fun startSchedulerPump() {
    if (schedulerPump != null) return
    val pump = Executors.newSingleThreadScheduledExecutor { r ->
      Thread(r, "daal-scheduler-pump").apply { isDaemon = true }
    }
    schedulerPump = pump
    // Zero initial delay: tunnel-up is the first moment a refresh that
    // has been failing offline can succeed.
    pump.scheduleWithFixedDelay({
      try {
        val rc = DaalCoreBridge.schedulerTick()
        // -1 means "engine not initialized yet" far more often than it
        // means "a refresh failed" — the engine itself treats a missed
        // tick as costing at most one cadence period — so this is
        // debug-level, not a warning that would train us to ignore it.
        if (rc < 0) Log.d(TAG, "scheduler tick returned $rc")
      } catch (t: Throwable) {
        // A throw here would kill the executor thread silently and
        // stop every future tick with no other symptom.
        Log.w(TAG, "scheduler tick threw: ${t.message}")
      }
    }, 0L, TICK_SECONDS, TimeUnit.SECONDS)
  }

  private fun stopSchedulerPump() {
    // shutdownNow, not shutdown: teardown() runs on the main thread and
    // must not block behind an in-flight tick that is inside a 15 s
    // network refresh. The engine's tick is safe to abandon — it drops
    // overlapping/late ticks by design.
    schedulerPump?.shutdownNow()
    schedulerPump = null
  }

  private fun promoteToForeground(routeId: String) {
    ensureChannel()
    val tapIntent = packageManager.getLaunchIntentForPackage(packageName)
    val pi = if (tapIntent != null) {
      PendingIntent.getActivity(
        this, 0, tapIntent,
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
      )
    } else null
    val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
      .setSmallIcon(android.R.drawable.ic_lock_lock)
      .setContentTitle("Daal")
      .setContentText("Tunnel active — $routeId")
      .setOngoing(true)
      .setContentIntent(pi)
      .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
      .build()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      startForeground(
        NOTIFICATION_ID, notif,
        android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
      )
    } else {
      startForeground(NOTIFICATION_ID, notif)
    }
  }

  private fun ensureChannel() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
    val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    if (nm.getNotificationChannel(CHANNEL_ID) != null) return
    val ch = NotificationChannel(
      CHANNEL_ID,
      "Daal tunnel",
      NotificationManager.IMPORTANCE_LOW,
    )
    ch.description = "Foreground notification while the Daal tunnel is active"
    nm.createNotificationChannel(ch)
  }

  companion object {
    const val ACTION_START = "org.daal.desktop.vpn.START"
    const val ACTION_STOP = "org.daal.desktop.vpn.STOP"
    const val EXTRA_ROUTE_ID = "route_id"
    const val NOTIFICATION_ID = 0xDAA1
    const val CHANNEL_ID = "daal.vpn"

    // Matches the desktop shell's 60 s cadence (src-tauri/src/lib.rs).
    // It is a floor on responsiveness, not a period: scheduler.Plan
    // decides what is actually due, and the shortest cadence it can be
    // asked for (a subscription's ProfileUpdateMin) is minutes.
    private const val TICK_SECONDS = 60L
    private const val TAG = "DaalVpnService"

    @Volatile private var connected: Boolean = false
    @Volatile private var activeRouteId: String? = null

    @JvmStatic fun isConnected(): Boolean = connected
    @JvmStatic fun currentRouteId(): String? = activeRouteId
  }
}
