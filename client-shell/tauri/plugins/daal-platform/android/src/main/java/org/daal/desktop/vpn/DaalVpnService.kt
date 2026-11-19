package org.daal.desktop.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.daal.desktop.platform.DaalCoreBridge
import org.daal.desktop.vpn.StartSequence.Outcome

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
 *   3. DaalCoreBridge.routePrecheck(routeId) — would the engine refuse
 *      this route? If so nothing below happens (see SWITCHING).
 *   4. ONLY IF NO TUN IS HELD: `Builder.establish()` the TUN inbound,
 *      hand the fd to the engine via DaalCoreBridge.setTunFd and detach
 *      it (the engine takes ownership; we must not close the
 *      ParcelFileDescriptor). A start that finds a TUN held is a switch
 *      and reuses it.
 *   5. Call DaalCoreBridge.setRoute(routeId) — this is what triggers
 *      Start() on the in-process driver.
 *   6. DaalCoreBridge.setTunnelRefresh(true) — put the engine's own
 *      scheduled fetches on the tunnel via its loopback SOCKS inlet.
 *   7. Start the scheduler pump (see startSchedulerPump).
 *
 * SWITCHING — a route is connected and Connect is tapped on another.
 * The old route must keep carrying traffic until the engine has
 * accepted the new one, and a new route that is refused or does not
 * carry must not leave the person disconnected. `Builder.establish()`
 * tears down the interface the old route is using, so a switch never
 * calls it: the TUN is built once per connection and the engine gives
 * each route's instance its own duplicate of it. What happens when the
 * new route does not come up is decided in StartSequence and
 * SwitchPolicy (pure, unit tested): the old route is kept if the engine
 * still carries it, reconnected if it does not, and only with nothing
 * to go back to does the service stop.
 *
 * On `ACTION_STOP` / `onRevoke` / `onDestroy`:
 *   1. stop the scheduler pump
 *   2. DaalCoreBridge.setTunnelRefresh(false)
 *   3. DaalCoreBridge.clearRoute()
 *   4. DaalCoreBridge.clearTunFd()  (engine closes the fd)
 *   5. stopForeground + stopSelf (at once, on the main thread; 1–4
 *      follow on the control thread — see THREADING).
 *
 * Ordering matters, and every pair below has a failure behind it:
 * registerProtectCallback before setTunFd, setTunFd before setRoute,
 * setRoute before setTunnelRefresh(true) (the inlet is not bound until
 * the instance starts), setTunnelRefresh(false) before clearRoute (never
 * advertise a dialer for a listener that is going away), clearRoute
 * before clearTunFd.
 *
 * THREADING — nothing that touches the engine runs on the main thread.
 *
 * `engine_set_route` does not return when the engine has started: it
 * returns when the engine has PROVED the route, by one real round trip
 * through it (core/engine/proof.go). That is a few milliseconds on a
 * good route, about 8 s on a dead one, up to ~30 s on a link that is
 * crawling, and minutes on a cold tor route. Service callbacks
 * (onStartCommand, onRevoke, onDestroy) run on the application's main
 * thread — the same thread that draws the WebView — so calling it there
 * froze the whole app for the length of the check and, past 5 s, earned
 * an "isn't responding" dialog on exactly the routes that do not work.
 *
 * So every engine call goes through ONE single-thread executor
 * (`control`), which is what keeps the ordering above: a start and the
 * teardown that follows it cannot interleave, they queue. The main
 * thread only does what must happen there promptly — startForeground
 * (Android kills a foreground service that has not called it within
 * 5 s), stopForeground, stopSelf — and returns.
 *
 * CANCELLING A CHECK. A Disconnect while the route is still being
 * checked must not wait behind the check it is trying to stop: the
 * teardown is queued BEHIND the blocked start. `engine_clear_route` is
 * the engine's cancel — it is safe from any thread, abandons a check in
 * flight at once (the blocked setRoute returns an error), and is
 * harmless when nothing is running — so a stop request calls it from a
 * short-lived thread of its own until the start has let go, and only
 * then does the queued teardown run. `generation` is how a start learns
 * it has been superseded: every start and every stop takes a new number,
 * and a start that is no longer the newest leaves at once, undoing
 * nothing — a stop's teardown is queued right behind it, and a newer
 * start carries on from the TUN and the route it leaves.
 *
 * A NEWER START cancels the same way, for the same reason (it is queued
 * behind the check of the start it replaces), with one difference:
 * clearRoute also disconnects a route that is CONNECTED, so it is
 * called only while the older start is actually inside its connection
 * check (SwitchPolicy.cancelStep).
 *
 * LOGGING. Every start, stop, supersede and teardown writes Log.i lines
 * with the generation, the route id and the return code of each engine
 * call (tag DaalVpnService). Route ids and closed codes only: nothing
 * read from a file, no address, no credential.
 *
 * The page shows "Checking the connection…" for as long as the check
 * runs: it reads `route_check: "verifying"` from the engine's
 * diagnostics, which it polls — vpnStart resolved long before.
 */
class DaalVpnService : VpnService() {

  /** Non-null exactly while the tunnel is up; see startSchedulerPump. */
  @Volatile private var schedulerPump: ScheduledExecutorService? = null

  private val mainHandler = Handler(Looper.getMainLooper())

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_START -> {
        val routeId = intent.getStringExtra(EXTRA_ROUTE_ID)
        if (routeId.isNullOrEmpty()) {
          Log.w(TAG, "ACTION_START with no route_id; ignoring")
          stopSelf()
          return START_NOT_STICKY
        }
        // Main thread: only what Android requires here, promptly.
        promoteToForeground(routeId)
        // Everything else — including the seconds-long connection
        // check inside setRoute — on the control thread.
        val gen: Int
        val previousStart: Int
        synchronized(lifecycleLock) {
          previousStart = lastStartGen
          gen = generation.incrementAndGet()
          lastStartGen = gen
        }
        Log.i(TAG, "start requested gen=$gen route=$routeId")
        if (finishedStartGen < previousStart) {
          // An older start is queued or running. This one is queued
          // BEHIND it on the control thread, and the older one may be
          // inside a connection check that lasts seconds (minutes, on a
          // cold tor route): it is cancelled, not waited for.
          Log.i(TAG, "supersede: start gen=$gen replaces start gen=$previousStart still in flight")
          cancelInFlight(previousStart, stopping = false)
        }
        control.execute {
          val outcome = try {
            start(routeId, gen)
          } catch (t: Throwable) {
            Log.e(TAG, "start gen=$gen route=$routeId threw: ${t.javaClass.simpleName}: ${t.message}")
            // Where it stopped is unknown, so nothing is assumed to be
            // up: release everything.
            teardownEngine("start gen=$gen threw")
            Outcome.DOWN
          } finally {
            // Under cancelLock: a cancel thread checks this and calls
            // clearRoute under the same lock, so once this start is
            // marked finished no late cancel can land on the start
            // queued behind it.
            synchronized(cancelLock) { finishedStartGen = gen }
          }
          Log.i(TAG, "start end gen=$gen route=$routeId outcome=$outcome connected=$connected on=${activeRouteId ?: "-"}")
          if (outcome == Outcome.DOWN && generation.get() == gen) {
            // Nothing is connected and nothing replaced this request:
            // there is no tunnel to keep a foreground service for. (If
            // a stop or a newer start superseded this one, the service's
            // fate is theirs to decide.)
            mainHandler.post {
              if (generation.get() == gen) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
              }
            }
          }
        }
        return START_STICKY
      }
      ACTION_STOP -> {
        requestStop("ACTION_STOP")
        stopSelf()
        return START_NOT_STICKY
      }
      else -> {
        // Restart after a system OOM kill: we don't have the route
        // id, so the safest behaviour is to stop and let the user
        // re-connect.
        Log.i(TAG, "onStartCommand with no action (restart after kill); stopping")
        stopSelf()
        return START_NOT_STICKY
      }
    }
  }

  override fun onRevoke() {
    requestStop("onRevoke")
    super.onRevoke()
  }

  override fun onDestroy() {
    requestStop("onDestroy")
    super.onDestroy()
  }

  /**
   * Runs on the control thread. The sequence itself — pre-check, TUN
   * only when none is held, setRoute, and what to do when the route
   * does not come up — is StartSequence (pure, unit tested); this
   * supplies the Android and engine halves of each step.
   */
  private fun start(routeId: String, gen: Int): Outcome {
    val host = object : StartSequence.Host {
      override fun superseded() = generation.get() != gen
      override fun tunHeld() = tunUp
      override fun lastGood() = lastGoodRouteId
      override fun setLastGood(routeId: String) { lastGoodRouteId = routeId }
      override fun registerProtect(): Int {
        // The protect callback runs on the binder thread the JNI hop
        // arrives on; calling VpnService.protect from there is fine per
        // Android docs.
        DaalCoreBridge.protectImpl = { fd -> protect(fd) }
        return DaalCoreBridge.registerProtectCallback()
      }
      override fun precheck(routeId: String) = this@DaalVpnService.precheck(routeId)
      override fun establishTun() = this@DaalVpnService.establishTun(gen)
      override fun retractRefresh() {
        try { DaalCoreBridge.setTunnelRefresh(false) } catch (_: Throwable) {}
      }
      override fun setRoute(routeId: String) = checkedSetRoute(routeId, gen)
      override fun engineView() = this@DaalVpnService.engineView()
      override fun routeIsUp(routeId: String) = this@DaalVpnService.routeIsUp(routeId, gen)
      override fun teardown(why: String) = teardownEngine("start gen=$gen: $why")
      override fun note(note: SwitchPolicy.SwitchNote?) { lastSwitch = note }
      override fun log(message: String) { Log.i(TAG, "start gen=$gen $message") }
    }
    return StartSequence(host).run(routeId)
  }

  /**
   * Control thread. Builds the TUN and hands it to the engine. Returns
   * null on success, else how the start ends.
   */
  private fun establishTun(gen: Int): Outcome? {
    fun superseded() = generation.get() != gen
    // addDisallowedApplication(self) is what keeps the engine's own
    // upstream sockets (sing-box outbounds to the relay) OUT of the
    // TUN. On Android the VPN captures every app's traffic INCLUDING
    // the VPN app's, so without this exclusion the engine's dial to
    // the relay loops back into the TUN. The pure-Go alternatives —
    // per-socket protect() bound to an auto-detected interface, or
    // net.Interfaces()/sysfs enumeration — are unusable here: the
    // untrusted-app SELinux domain denies netlink RTM_GETLINK,
    // /proc/net/*, and /sys/class/net alike, so the engine can never
    // learn an interface to bind to. Excluding our own package makes
    // the exclusion at the routing layer, needs no interface list,
    // and lets the engine dial normally (auto_detect_interface off).
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
      Log.e(TAG, "start gen=$gen addDisallowedApplication(self) failed: ${e.message}")
      DaalCoreBridge.protectImpl = null
      return Outcome.DOWN
    }
    // We hold the ParcelFileDescriptor until the engine has accepted
    // ownership so that on rejection we can close it cleanly (avoids a
    // fd leak).
    val pfd: ParcelFileDescriptor = builder.establish()
      ?: run {
        Log.w(TAG, "start gen=$gen VpnService.Builder.establish() returned null (VPN permission lost?)")
        DaalCoreBridge.protectImpl = null
        return Outcome.DOWN
      }
    if (superseded()) {
      // Superseded while the interface was being built: the engine has
      // seen nothing of this start yet.
      Log.i(TAG, "start gen=$gen superseded while the TUN was being built; closing it")
      try { pfd.close() } catch (_: Throwable) {}
      return Outcome.SUPERSEDED
    }

    // Hand the fd to the engine. Use ParcelFileDescriptor.getFd()
    // first so we can still close(pfd) if the engine rejects it;
    // on success we detach so the engine owns the lifetime.
    val setRc = DaalCoreBridge.setTunFd(pfd.fd)
    Log.i(TAG, "start gen=$gen set_tun_fd_rc=$setRc")
    if (setRc < 0) {
      try { pfd.close() } catch (_: Throwable) {}
      DaalCoreBridge.protectImpl = null
      return Outcome.DOWN
    }
    // Engine accepted ownership; detach so close-on-pfd does not touch
    // the copy the engine now owns. It keeps that copy until
    // clearTunFd and gives each route's instance a duplicate, which is
    // why the next start can switch routes without a new TUN.
    pfd.detachFd()
    tunUp = true
    return null
  }

  /**
   * Control thread. `engine_set_route`, marked so that a newer start
   * can tell this one is inside the connection check and cancel it
   * (SwitchPolicy.cancelStep). Returns the engine's code, or
   * RC_SUPERSEDED without calling the engine when this start is no
   * longer the newest request.
   */
  private fun checkedSetRoute(routeId: String, gen: Int): Int {
    val go = synchronized(cancelLock) {
      if (generation.get() != gen) {
        false
      } else {
        checkingGen = gen
        true
      }
    }
    if (!go) return RC_SUPERSEDED
    try {
      return DaalCoreBridge.setRoute(routeId)
    } finally {
      synchronized(cancelLock) { checkingGen = 0 }
    }
  }

  /**
   * Control thread. The engine is carrying [routeId]; make the service
   * say so, unless a stop or a newer start arrived meanwhile.
   */
  private fun routeIsUp(routeId: String, gen: Int): Outcome {
    fun superseded() = generation.get() != gen
    // Decided under the lock a stop takes; acted on outside it, so the
    // main thread never waits on an engine call.
    val lost = synchronized(lifecycleLock) {
      if (superseded()) {
        true
      } else {
        activeRouteId = routeId
        connected = true
        false
      }
    }
    if (lost) {
      Log.i(TAG, "start gen=$gen superseded just after route=$routeId came up; leaving the rest to the newer request")
      return Outcome.SUPERSEDED
    }

    // Put the engine's OWN fetches on the tunnel, before anything
    // starts asking for them.
    //
    // setRoute returning 0 means the in-process sing-box instance
    // started, which means it has already bound every inbound in its
    // config — including the loopback SOCKS5 refresh inlet. Only then
    // does the engine publish that inlet, and only then does this call
    // succeed. So the listener provably exists before the refresher is
    // ever handed a dialer that points at it; there is no window in
    // which a due refresh dials a dead port.
    //
    // A failure here is NOT fatal to the connection: the tunnel works
    // either way, and the engine's fetches stay fail-closed
    // (refresh.ErrTunnelRequired) rather than falling back to a direct
    // dial from the user's real address. Losing scheduled refresh is a
    // degradation; leaking the address is not one we take. Log it and
    // carry on.
    val refreshRc = try {
      DaalCoreBridge.setTunnelRefresh(true)
    } catch (e: Throwable) {
      Log.e(TAG, "engine_set_tunnel_refresh threw: ${e.message}")
      -1
    }
    if (refreshRc < 0) {
      Log.w(
        TAG,
        "start gen=$gen set_tunnel_refresh_rc=$refreshRc; scheduled refresh " +
          "stays disabled for this session (fail-closed, not direct-dial)",
      )
    } else {
      Log.i(TAG, "start gen=$gen set_tunnel_refresh_rc=$refreshRc")
    }

    // Now start ticking (a no-op when the pump is already running, as
    // on a switch). The pump comes last on purpose: a tick that finds
    // work due dispatches refreshes inline, and the step above is what
    // decides whether those can go anywhere at all. Under the lock, and
    // only if no stop has arrived: a stop stops the pump under the same
    // lock, so it can never be started after one. (A stop that arrived
    // since has queued its teardown behind this start, on this thread;
    // it undoes all of this next.)
    synchronized(lifecycleLock) {
      if (!superseded()) startSchedulerPump()
    }
    // The notification was set to the route that was asked for; it may
    // not be the route that is up.
    mainHandler.post {
      if (generation.get() == gen && connected) promoteToForeground(routeId)
    }
    return Outcome.UP
  }

  /** `engine_route_precheck`, or null when it cannot be asked. */
  private fun precheck(routeId: String): SwitchPolicy.EngineView? {
    val raw = try {
      DaalCoreBridge.routePrecheck(routeId)
    } catch (t: Throwable) {
      Log.w(TAG, "route pre-check unavailable: ${t.javaClass.simpleName}")
      null
    } ?: return null
    return try {
      val o = JSONObject(raw)
      SwitchPolicy.EngineView(
        activeRoute = if (o.isNull("active_route")) null else o.optString("active_route", ""),
        routeRunning = null,
        refusedCode = o.optString("refused", ""),
        refusedRoute = routeId,
        failedCategory = "",
      )
    } catch (t: Throwable) {
      Log.w(TAG, "route pre-check answer was not readable: ${t.javaClass.simpleName}")
      null
    }
  }

  /** What the engine says about the connection now, or null. */
  private fun engineView(): SwitchPolicy.EngineView? {
    val raw = try {
      DaalCoreBridge.engineState()
    } catch (t: Throwable) {
      Log.w(TAG, "engine state unavailable: ${t.javaClass.simpleName}")
      null
    } ?: return null
    return try {
      val o = JSONObject(raw)
      SwitchPolicy.EngineView(
        activeRoute = if (o.isNull("active_route")) null else o.optString("active_route", ""),
        routeRunning = if (o.isNull("route_running")) null else o.optBoolean("route_running"),
        refusedCode = o.optString("connect_refused", ""),
        refusedRoute = o.optString("connect_refused_route", ""),
        failedCategory = o.optString("route_check_category", ""),
      )
    } catch (t: Throwable) {
      Log.w(TAG, "engine state was not readable: ${t.javaClass.simpleName}")
      null
    }
  }

  /**
   * Main thread (ACTION_STOP, onRevoke, onDestroy). Returns at once:
   * supersedes any start, stops the pump, cancels a connection check in
   * flight, and queues the engine teardown behind whatever the control
   * thread is doing. Safe to call any number of times.
   */
  private fun requestStop(why: String) {
    val pendingStart: Int
    val gen: Int
    synchronized(lifecycleLock) {
      gen = generation.incrementAndGet()
      pendingStart = lastStartGen
      // Before the dialer is retracted (in teardownEngine), as always.
      stopSchedulerPump()
    }
    val inFlight = finishedStartGen < pendingStart
    Log.i(
      TAG,
      "stop requested ($why) gen=$gen connected=$connected on=${activeRouteId ?: "-"}" +
        if (inFlight) " — supersedes start gen=$pendingStart still in flight" else "",
    )
    // The person asked to disconnect: an older note about a switch that
    // did not take has nothing left to explain.
    lastSwitch = null
    if (inFlight) {
      // A start is queued or running and may be inside the engine's
      // connection check; the teardown below is queued BEHIND it.
      cancelInFlight(pendingStart, stopping = true)
    }
    control.execute { teardownEngine("stop gen=$gen ($why)") }
    stopForeground(STOP_FOREGROUND_REMOVE)
  }

  /**
   * Cancels the start numbered [pendingStart] from a short-lived thread
   * of its own, so that whoever superseded it (a stop on the main
   * thread, a newer start queued behind it on the control thread) does
   * not wait for its connection check. The engine's cancel is
   * clearRoute; when it may be called is SwitchPolicy.cancelStep. The
   * loop ends the moment that start has finished (starts run in order
   * on one thread, so "finished" is a number), and is bounded
   * regardless.
   */
  private fun cancelInFlight(pendingStart: Int, stopping: Boolean) {
    val t = Thread {
      var waited = 0L
      var cancels = 0
      var finished = false
      while (waited < CANCEL_MAX_MS) {
        val step = synchronized(cancelLock) {
          val s = SwitchPolicy.cancelStep(stopping, pendingStart, finishedStartGen, checkingGen)
          if (s == SwitchPolicy.CancelStep.CANCEL) {
            try { DaalCoreBridge.clearRoute() } catch (_: Throwable) {}
            cancels++
          }
          s
        }
        if (step == SwitchPolicy.CancelStep.DONE) {
          finished = true
          break
        }
        try { Thread.sleep(CANCEL_POLL_MS) } catch (_: InterruptedException) { break }
        waited += CANCEL_POLL_MS
      }
      Log.i(
        TAG,
        "cancel of start gen=$pendingStart ended: finished=$finished clear_route_calls=$cancels " +
          "waited_ms=$waited by=${if (stopping) "stop" else "newer start"}",
      )
    }
    t.name = "daal-vpn-cancel"
    t.isDaemon = true
    t.start()
  }

  /**
   * Control thread only (never under lifecycleLock: the main thread
   * takes that lock and must not wait on the engine). Idempotent: on an
   * engine that is already down every call below is a no-op.
   */
  private fun teardownEngine(why: String) {
    val wasOn = activeRouteId
    val hadTun = tunUp
    connected = false
    activeRouteId = null
    lastGoodRouteId = null
    tunUp = false
    // Retract the tunnel dialer BEFORE the route (and with it the
    // loopback inlet) goes away, so no in-flight or newly-started fetch
    // can be handed a dialer pointing at a listener that is already
    // closing. The engine clears the same state itself when the driver
    // stops — this is belt and braces, and it makes the ordering
    // readable from the host side, which is where the mistake would be
    // made.
    val refreshRc = try { DaalCoreBridge.setTunnelRefresh(false) } catch (_: Throwable) { RC_THREW }
    val routeRc = try { DaalCoreBridge.clearRoute() } catch (_: Throwable) { RC_THREW }
    val tunRc = try { DaalCoreBridge.clearTunFd() } catch (_: Throwable) { RC_THREW }
    DaalCoreBridge.protectImpl = null
    Log.i(
      TAG,
      "teardown ($why): was_on=${wasOn ?: "-"} tun_held=$hadTun " +
        "set_tunnel_refresh_rc=$refreshRc clear_route_rc=$routeRc clear_tun_fd_rc=$tunRc",
    )
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
   *      retracted in teardownEngine(). Keep that order.
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
    // shutdownNow, not shutdown: requestStop() runs on the main thread
    // and must not block behind an in-flight tick that is inside a 15 s
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

    // How often a stop repeats the engine's cancel while a start is in
    // flight, and for how long at most (longer than any connection
    // check the engine makes on a route that is not tor).
    private const val CANCEL_POLL_MS = 100L
    private const val CANCEL_MAX_MS = 60_000L

    // Not engine return codes: this side's own, for the log.
    private const val RC_SUPERSEDED = -2
    private const val RC_THREW = -3

    @Volatile private var connected: Boolean = false
    @Volatile private var activeRouteId: String? = null

    /**
     * CONTROL THREAD ONLY. True while the engine holds a TUN this
     * service established and has not released (clearTunFd). A start
     * that finds it true is a switch and builds no new TUN.
     */
    private var tunUp: Boolean = false

    /**
     * CONTROL THREAD ONLY. The route that last passed its connection
     * check on the TUN held — what a failed switch stays on or goes
     * back to. Null when nothing has connected since the TUN was built.
     */
    private var lastGoodRouteId: String? = null

    /**
     * The generation of the start that is inside `engine_set_route`
     * right now, 0 when none is. Written under cancelLock.
     */
    @Volatile private var checkingGen: Int = 0

    /** The last switch that did not take; see SwitchPolicy.SwitchNote. */
    @Volatile private var lastSwitch: SwitchPolicy.SwitchNote? = null

    /**
     * The one thread engine lifecycle calls are made on. Process-wide,
     * not per service instance: Android may destroy one instance and
     * create another between a stop and the next start, and the two
     * must still queue behind each other.
     */
    private val control: ExecutorService = Executors.newSingleThreadExecutor { r ->
      Thread(r, "daal-vpn-control").apply { isDaemon = true }
    }

    /** Guards generation/starting/connected transitions and the pump. */
    private val lifecycleLock = Any()

    /** Bumped by every start and every stop; the newest request wins. */
    private val generation = AtomicInteger(0)

    /**
     * The generation of the newest START request, and of the newest
     * start the control thread has FINISHED (succeeded, failed or
     * abandoned). Starts run in request order on one thread, so
     * `finishedStartGen < lastStartGen` is exactly "a start is queued
     * or running".
     */
    @Volatile private var lastStartGen: Int = 0
    @Volatile private var finishedStartGen: Int = 0

    /**
     * Serialises "this start is finished" and "this start is inside
     * setRoute" with a cancel thread's clearRoute call.
     */
    private val cancelLock = Any()

    @JvmStatic fun isConnected(): Boolean = connected
    @JvmStatic fun currentRouteId(): String? = activeRouteId
    @JvmStatic fun lastSwitchNote(): SwitchPolicy.SwitchNote? = lastSwitch
  }
}
