package org.daal.desktop.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.util.Log
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.net.Inet4Address
import java.net.Inet6Address
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.daal.desktop.platform.DaalCoreBridge
import org.daal.desktop.platform.R
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
 * AUTOMATIC CONNECT — `ACTION_START` with no route id (and a start by
 * the system: always-on VPN, a restart after the process was killed).
 * The service does not choose a route. Steps 1–2, then step 4 (a TUN
 * only if none is held), then DaalCoreBridge.connectAuto(): the engine
 * picks among every usable route, tries them in order and keeps the
 * first that carries (StartSequence.runAuto). The route it ended on is
 * what the service reports; when it found none, the engine's verdict
 * code is left in the note vpnStatus carries and everything is
 * released.
 *
 * While connected this way THE ENGINE MAY MOVE TO ANOTHER ROUTE BY
 * ITSELF when the one in use stops carrying. That is not an error and
 * needs nothing rebuilt (the TUN is the service's and stays). The
 * service only follows: `followOnce` reads the engine's state every
 * FOLLOW_SECONDS, and whenever the page asks for vpnStatus, and
 * publishes the route that is actually running (SwitchPolicy.follow).
 * If the engine runs out of routes, the TUN is KEPT — the person did
 * not ask to be disconnected, and releasing it would put their traffic
 * back on the open network without a word — and the service asks the
 * engine to search again, backing off (SwitchPolicy.retryDelayMs),
 * until a route carries or the person disconnects. The notification
 * names no route in this mode.
 *
 * THE NETWORK UNDER THE TUNNEL. The engine cannot see the phone's
 * network; this service can, and tells it (DaalCoreBridge.networkFacts:
 * kind, an opaque id, validated, metered). A
 * ConnectivityManager.NetworkCallback is registered from the first
 * start until the stop — also while holding, which is when "the
 * network is back" matters most — for the DEFAULT network of this app.
 * That is the network under the tunnel and never the tunnel itself:
 * the app is excluded from its own VPN (establishTun), so its default
 * network is the real one, and an event that is about a VPN network
 * all the same is dropped. What is sent and when — the first facts at
 * once, later changes after they settle, identical facts once, a lost
 * network as kind "none" — is NetworkWatch (pure, unit tested). The
 * engine calls are made on a thread of their own (`network`), never
 * the control thread: a connect in flight there can block for the
 * whole search, and that is exactly when the engine should learn that
 * the phone has no network. While holding, a network that has just
 * appeared (or just been validated) starts a search at once instead of
 * waiting out the retry backoff (NetworkWatch.retryNow). Needs ACCESS_NETWORK_STATE
 * (a normal permission: no dialog), declared in this module's
 * manifest. No location permission: no SSID is read.
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

  /** MAIN THREAD ONLY. Non-null exactly while the callback is registered. */
  private var netCallback: ConnectivityManager.NetworkCallback? = null

  /** Decides what the engine is told about the network, and when. */
  private val netWatch = NetworkWatch()

  /** Main thread. Asks [netWatch] what is due and sends it. */
  private val netFlush = Runnable { flushNetwork() }

  override fun onCreate() {
    super.onCreate()
    live = this
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_START -> {
        // No route id = connect automatically: the engine picks.
        val routeId = intent.getStringExtra(EXTRA_ROUTE_ID)?.trim().orEmpty()
        beginStart(routeId.ifEmpty { null }, reconnect = false, attempt = 0, why = "ACTION_START")
        return START_STICKY
      }
      ACTION_STOP -> {
        requestStop("ACTION_STOP")
        stopSelf()
        return START_NOT_STICKY
      }
      else -> {
        // Started by the system, with no route: always-on VPN (and the
        // start at boot that comes with it), or a restart after the
        // process was killed. There is no route id to go back to and
        // none is needed — the engine picks. When the engine is not
        // loaded in this process (it is loaded by the app's activity),
        // runAuto finds that out before it builds anything, and the
        // service stops as it always did.
        Log.i(TAG, "onStartCommand by the system (action=${if (intent == null) "none" else "other"}); connecting automatically")
        beginStart(null, reconnect = false, attempt = 0, why = "system start")
        return START_STICKY
      }
    }
  }

  /**
   * Main thread. Queues a start on the control thread: of [routeId], or
   * — when it is null — an automatic connect. [reconnect] marks the
   * service's own retry after the engine ran out of routes ([attempt]
   * counts them); it is never set for a request by a person.
   */
  private fun beginStart(routeId: String?, reconnect: Boolean, attempt: Int, why: String) {
    val auto = routeId == null
    // Main thread: only what Android requires here, promptly. A start
    // by the system may not be allowed to go foreground (Android 12+,
    // from the background); the connect is still attempted.
    try {
      promoteToForeground(
        when {
          reconnect -> noteHolding()
          auto -> getString(R.string.daal_vpn_note_connecting)
          else -> noteActive(routeId)
        },
      )
    } catch (t: Throwable) {
      Log.w(TAG, "could not go foreground ($why): ${t.javaClass.simpleName}")
    }
    // Before the connect is queued: the engine should know what
    // network it is on (or that there is none) while it searches.
    // [firstFacts] is released once the first report has reached the
    // engine (null: the watch was already running, or Android has not
    // described the network yet); the connect below waits for it.
    val firstFacts = startNetworkWatch()
    // Everything else — including the seconds-long connection
    // check inside setRoute / connectAuto — on the control thread.
    val gen: Int
    val previousStart: Int
    synchronized(lifecycleLock) {
      previousStart = lastStartGen
      gen = generation.incrementAndGet()
      lastStartGen = gen
      // A route picked by hand takes the connection back from the
      // engine's automatic connect; an automatic start hands it over.
      autoMode = auto
    }
    val what = if (auto) "auto" else "route=$routeId"
    Log.i(TAG, "start requested gen=$gen $what ($why)" + if (reconnect) " retry=$attempt" else "")
    if (finishedStartGen < previousStart) {
      // An older start is queued or running. This one is queued
      // BEHIND it on the control thread, and the older one may be
      // inside a connection check that lasts seconds (minutes, on a
      // cold tor route): it is cancelled, not waited for.
      Log.i(TAG, "supersede: start gen=$gen replaces start gen=$previousStart still in flight")
      cancelInFlight(previousStart, stopping = false)
    }
    control.execute {
      // The engine's order of routes, and whether it tries one alone or
      // two together, depend on which network it believes it is on.
      // Bounded: a connect is never held up for long by a report.
      try {
        if (firstFacts != null && !firstFacts.await(NetworkWatch.FIRST_FACTS_WAIT_MS, TimeUnit.MILLISECONDS)) {
          Log.w(TAG, "network: the first report had not reached the engine when start gen=$gen began")
        }
      } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
      }
      val outcome = try {
        start(routeId, gen, reconnect)
      } catch (t: Throwable) {
        Log.e(TAG, "start gen=$gen $what threw: ${t.javaClass.simpleName}: ${t.message}")
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
      Log.i(TAG, "start end gen=$gen $what outcome=$outcome connected=$connected on=${activeRouteId ?: "-"}")
      if (outcome == Outcome.DOWN && generation.get() == gen) {
        // Nothing is connected and nothing replaced this request:
        // there is no tunnel to keep a foreground service for. (If
        // a stop or a newer start superseded this one, the service's
        // fate is theirs to decide.)
        mainHandler.post {
          if (generation.get() == gen) {
            stopNetworkWatch()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
          }
        }
      }
      if (outcome == Outcome.HOLDING) scheduleRetry(gen, attempt + 1)
    }
  }

  /**
   * Any thread. The engine ran out of routes while the person was
   * connected automatically; ask it to search again after a pause.
   * Dropped if anything else is asked for in the meantime (a stop, a
   * route picked by hand, another Connect): [gen] is then no longer the
   * newest request.
   */
  private fun scheduleRetry(gen: Int, attempt: Int) {
    val delay = SwitchPolicy.retryDelayMs(attempt)
    Log.i(TAG, "auto: retry=$attempt in ${delay / 1000}s (after gen=$gen)")
    mainHandler.postDelayed({
      if (generation.get() == gen && autoMode && !connected) {
        beginStart(null, reconnect = true, attempt = attempt, why = "retry")
      }
    }, delay)
  }

  override fun onRevoke() {
    requestStop("onRevoke")
    super.onRevoke()
  }

  override fun onDestroy() {
    requestStop("onDestroy")
    if (live === this) live = null
    super.onDestroy()
  }

  /**
   * Runs on the control thread. The sequence itself — pre-check, TUN
   * only when none is held, setRoute, and what to do when the route
   * does not come up — is StartSequence (pure, unit tested); this
   * supplies the Android and engine halves of each step.
   */
  private fun start(routeId: String?, gen: Int, reconnect: Boolean): Outcome {
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
      override fun connectAuto() = checkedConnectAuto(gen)
      override fun hold(verdict: String) = this@DaalVpnService.hold(gen)
      override fun engineView() = this@DaalVpnService.engineView()
      override fun routeIsUp(routeId: String) = this@DaalVpnService.routeIsUp(routeId, gen)
      override fun teardown(why: String) = teardownEngine("start gen=$gen: $why")
      override fun note(note: SwitchPolicy.SwitchNote?) { lastSwitch = note }
      override fun log(message: String) { Log.i(TAG, "start gen=$gen $message") }
    }
    val sequence = StartSequence(host)
    return if (routeId == null) sequence.runAuto(reconnect) else sequence.run(routeId)
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
   * Control thread. `engine_connect_auto`, marked exactly as
   * [checkedSetRoute] marks a setRoute: the engine's cancel
   * (clearRoute) abandons the whole search, including the connection
   * check in flight, so a stop or a newer start does not wait behind
   * it. Null when this start is no longer the newest request, when the
   * engine cannot be asked, or when it has no such call.
   */
  private fun checkedConnectAuto(gen: Int): SwitchPolicy.AutoResult? {
    val go = synchronized(cancelLock) {
      if (generation.get() != gen) {
        false
      } else {
        checkingGen = gen
        true
      }
    }
    if (!go) return null
    val raw = try {
      DaalCoreBridge.connectAuto()
    } catch (t: Throwable) {
      // UnsatisfiedLinkError included: a native library older than
      // this class.
      Log.w(TAG, "start gen=$gen automatic connect unavailable: ${t.javaClass.simpleName}")
      null
    } finally {
      synchronized(cancelLock) { checkingGen = 0 }
    } ?: return null
    return try {
      val o = JSONObject(raw)
      SwitchPolicy.AutoResult(
        connected = o.optBoolean("connected", false),
        routeId = o.optString("route_id", ""),
        verdict = o.optString("verdict", ""),
        tried = o.optInt("tried", 0),
        candidates = o.optInt("candidates", 0),
      )
    } catch (t: Throwable) {
      Log.w(TAG, "start gen=$gen automatic connect answer was not readable: ${t.javaClass.simpleName}")
      null
    }
  }

  /**
   * Control thread. Nothing is connected any more but the TUN stays
   * (see AUTOMATIC CONNECT): stop saying a route is up, and take the
   * engine's own fetches off a route that is gone. They fail closed
   * until a route is up again.
   */
  private fun hold(gen: Int) {
    val lost = synchronized(lifecycleLock) {
      if (generation.get() != gen) {
        true
      } else {
        connected = false
        activeRouteId = null
        false
      }
    }
    if (lost) return
    lastGoodRouteId = null
    try { DaalCoreBridge.setTunnelRefresh(false) } catch (_: Throwable) {}
    mainHandler.post {
      if (generation.get() == gen && !connected) {
        try { promoteToForeground(noteHolding()) } catch (_: Throwable) {}
      }
    }
  }

  // ---------------------------------------------------------------
  // The network under the tunnel (see the class comment).
  // ---------------------------------------------------------------

  /**
   * Main thread. Idempotent: a switch or a retry finds it running.
   *
   * Returns a latch that opens when the FIRST facts have been handed to
   * the engine, when Android could describe the default network right
   * here (it usually can); null otherwise.
   */
  private fun startNetworkWatch(): CountDownLatch? {
    if (netCallback != null) return null
    val cm = try {
      getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    } catch (_: Throwable) {
      null
    }
    if (cm == null) {
      Log.w(TAG, "network: no ConnectivityManager; the engine is not told about the network")
      return null
    }
    val cb = object : ConnectivityManager.NetworkCallback() {
      override fun onAvailable(network: Network) {
        netEvent(netWatch.available(network.networkHandle, netNow()))
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
          // Before Android 8 the two descriptions below are not
          // promised to follow by themselves; ask once.
          try {
            cm.getNetworkCapabilities(network)?.let { onCapabilitiesChanged(network, it) }
            cm.getLinkProperties(network)?.let { onLinkPropertiesChanged(network, it) }
          } catch (_: Throwable) {}
        }
      }

      override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
        netEvent(netWatch.capabilities(network.networkHandle, capsOf(caps), netNow()))
      }

      override fun onLinkPropertiesChanged(network: Network, link: LinkProperties) {
        netEvent(netWatch.link(network.networkHandle, linkOf(link), netNow()))
      }

      override fun onLost(network: Network) {
        netEvent(netWatch.lost(network.networkHandle, netNow()))
      }
    }
    try {
      // Android calls nothing back when there is no network at all, so
      // whether one exists is asked once, before listening.
      val active = cm.activeNetwork
      val has = active != null
      lastNetFacts = null
      lastNetRetryAt = 0L
      // What Android already knows about it, asked once: the callbacks
      // say the same a moment later, by way of two more threads, and
      // the connect must not start before the engine has been told.
      var first: NetworkWatch.Facts? = null
      if (active != null) {
        val caps = try { cm.getNetworkCapabilities(active)?.let { capsOf(it) } } catch (_: Throwable) { null }
        val link = try { cm.getLinkProperties(active)?.let { linkOf(it) } } catch (_: Throwable) { null }
        first = netWatch.startDescribed(active.networkHandle, caps, link, netNow())
        netEvent(netWatch.nextIn(netNow()))
      } else {
        netEvent(netWatch.start(false, netNow()))
        first = netWatch.due(netNow())
      }
      cm.registerDefaultNetworkCallback(cb)
      netCallback = cb
      reportingNetwork = true
      Log.i(TAG, "network: watching (a default network ${if (has) "exists" else "does not exist"}; described at once=${first != null})")
      val facts = first ?: return null
      val latch = CountDownLatch(1)
      network.execute {
        try {
          sendNetwork(facts)
        } finally {
          latch.countDown()
        }
      }
      return latch
    } catch (t: Throwable) {
      // SecurityException without ACCESS_NETWORK_STATE in the merged
      // manifest; RuntimeException past the system's callback limit.
      netWatch.stop()
      mainHandler.removeCallbacks(netFlush)
      Log.w(TAG, "network: could not watch: ${t.javaClass.simpleName}; the engine is not told about the network")
      return null
    }
  }

  /** Main thread. Idempotent. */
  private fun stopNetworkWatch() {
    val cb = netCallback ?: return
    netCallback = null
    reportingNetwork = false
    netWatch.stop()
    mainHandler.removeCallbacks(netFlush)
    lastNetFacts = null
    try {
      (getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager)?.unregisterNetworkCallback(cb)
    } catch (_: Throwable) {}
    Log.i(TAG, "network: no longer watching")
  }

  private fun netNow() = SystemClock.elapsedRealtime()

  /** Any thread. [delayMs] is what a [NetworkWatch] call answered. */
  private fun netEvent(delayMs: Long?) {
    if (delayMs == null) return
    mainHandler.removeCallbacks(netFlush)
    mainHandler.postDelayed(netFlush, delayMs)
  }

  /** Main thread. */
  private fun flushNetwork() {
    if (netCallback == null) return
    val facts = netWatch.due(netNow())
    if (facts != null) network.execute { sendNetwork(facts) }
    netEvent(netWatch.nextIn(netNow()))
  }

  /**
   * `network` thread. One engine call. The log line carries the kind
   * and the two flags; of the id only whether there is one.
   */
  private fun sendNetwork(facts: NetworkWatch.Facts) {
    if (!reportingNetwork) return
    val rc = try {
      DaalCoreBridge.networkFacts(facts.kind, facts.id, facts.validated, facts.metered)
    } catch (t: Throwable) {
      RC_THREW
    }
    Log.i(
      TAG,
      "network: kind=${facts.kind} validated=${facts.validated} metered=${facts.metered} " +
        "id=${if (facts.id.isEmpty()) "none" else "set"} engine_rc=$rc",
    )
    netEvent(netWatch.delivered(facts, rc >= 0, netNow()))
    if (rc < 0) return
    val before = lastNetFacts
    lastNetFacts = facts
    val gen = generation.get()
    // Only a search the service itself would start: an automatic
    // connect in charge, the interface held, nothing connected, and no
    // start queued or running (a pass in flight is not replaced).
    fun idleHolding() =
      generation.get() == gen && isHolding() && finishedStartGen == lastStartGen
    if (!idleHolding()) return
    val now = netNow()
    val retry = NetworkWatch.retryNow(true, before, facts, now - lastNetRetryAt)
    if (retry) lastNetRetryAt = now
    mainHandler.post {
      if (!idleHolding()) return@post
      if (retry) {
        Log.i(TAG, "network: a network to try while holding; searching now (after gen=$gen)")
        beginStart(null, reconnect = true, attempt = 1, why = "network is back")
      } else {
        // Still holding: say whether it is the phone that has no network.
        try { promoteToForeground(noteHolding()) } catch (_: Throwable) {}
      }
    }
  }

  private fun capsOf(caps: NetworkCapabilities): NetworkWatch.Caps {
    val cellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
    return NetworkWatch.Caps(
      wifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
      cellular = cellular,
      ethernet = caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
      vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
        !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
      validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
      notMetered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ||
        (
          Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_TEMPORARILY_NOT_METERED)
          ),
      operator = if (cellular) simOperator() else "",
    )
  }

  /**
   * The operator code of the SIM that carries mobile data (digits; ""
   * when it cannot be read). Needs no permission. It is the SIM's
   * operator, not the tower's, so it does not change while roaming.
   */
  private fun simOperator(): String = try {
    var tm = getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
    val sub = SubscriptionManager.getDefaultDataSubscriptionId()
    if (tm != null && sub != SubscriptionManager.INVALID_SUBSCRIPTION_ID) tm = tm.createForSubscriptionId(sub)
    tm?.simOperator.orEmpty()
  } catch (_: Throwable) {
    ""
  }

  private fun linkOf(link: LinkProperties): NetworkWatch.Link {
    val subnets = ArrayList<String>()
    var gw4 = ""
    var gw6 = ""
    try {
      for (la in link.linkAddresses) {
        val a = la.address
        if (a is Inet4Address) subnets.add(NetworkWatch.subnet(a.address, la.prefixLength))
      }
      for (r in link.routes) {
        if (!r.isDefaultRoute) continue
        val g = r.gateway ?: continue
        if (g.isAnyLocalAddress) continue
        if (g is Inet4Address && gw4.isEmpty()) gw4 = g.hostAddress.orEmpty()
        if (g is Inet6Address && gw6.isEmpty()) gw6 = g.hostAddress.orEmpty()
      }
    } catch (_: Throwable) {}
    return NetworkWatch.Link(subnets, gw4, gw6)
  }

  /**
   * Any thread. Queue one look at the engine's own state on the control
   * thread, if an automatic connect is in charge and none is queued.
   */
  private fun queueFollow() {
    if (!autoMode) return
    if (!followQueued.compareAndSet(false, true)) return
    control.execute {
      try {
        followOnce()
      } catch (t: Throwable) {
        Log.w(TAG, "follow threw: ${t.javaClass.simpleName}")
      } finally {
        followQueued.set(false)
      }
    }
  }

  /**
   * Control thread. While the engine's automatic connect is in charge
   * it may have moved to another route, or run out of routes, since the
   * last look. Does nothing unless the newest request is an automatic
   * start that has finished and still holds its TUN — a start in flight
   * or a stop decides for itself.
   */
  private fun followOnce() {
    val gen = generation.get()
    if (!autoMode || gen != lastStartGen || finishedStartGen != gen || !tunUp) return
    when (val f = SwitchPolicy.follow(activeRouteId, engineView())) {
      SwitchPolicy.Follow.None -> {}
      is SwitchPolicy.Follow.Moved -> {
        val was = activeRouteId
        val lost = synchronized(lifecycleLock) {
          if (generation.get() != gen) {
            true
          } else {
            activeRouteId = f.routeId
            connected = true
            false
          }
        }
        if (lost) return
        lastGoodRouteId = f.routeId
        // Whatever an earlier attempt left to explain is over.
        lastSwitch = null
        // The engine's own fetches rode the instance that is gone; the
        // new instance has its own inlet. Fail-closed if this fails.
        val refreshRc = try { DaalCoreBridge.setTunnelRefresh(true) } catch (_: Throwable) { RC_THREW }
        Log.i(
          TAG,
          "auto: the engine moved by itself from=${was ?: "-"} to=${f.routeId} " +
            "why=${if (f.faster) "faster" else "not_carrying"} " +
            "set_tunnel_refresh_rc=$refreshRc (gen=$gen)",
        )
        mainHandler.post {
          if (generation.get() == gen && connected) {
            try { promoteToForeground(noteActive(null)) } catch (_: Throwable) {}
          }
        }
      }
      is SwitchPolicy.Follow.Lost -> {
        // Already holding: a retry is scheduled.
        if (!connected) return
        val verdict = f.verdict.ifEmpty { "all_failed" }
        Log.i(TAG, "auto: the engine ran out of routes (verdict=$verdict) on=${activeRouteId ?: "-"}; keeping the TUN closed (gen=$gen)")
        hold(gen)
        lastSwitch = SwitchPolicy.describeAutoFailure(null, verdict)
        scheduleRetry(gen, 1)
      }
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
    // not be the route that is up. In automatic mode it names none: the
    // engine may change route without telling anyone.
    mainHandler.post {
      if (generation.get() == gen && connected) {
        try {
          promoteToForeground(noteActive(if (autoMode) null else routeId))
        } catch (t: Throwable) {
          Log.w(TAG, "could not update the notification: ${t.javaClass.simpleName}")
        }
      }
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
        autoMode = if (o.isNull("auto_mode")) null else o.optBoolean("auto_mode"),
        autoState = o.optString("auto_state", ""),
        autoVerdict = o.optString("auto_verdict", ""),
        switchBackRoute = o.optString("switch_back_route", ""),
        switchBackCategory = o.optString("switch_back_category", ""),
        switchBackRestored = if (o.isNull("switch_back_restored")) null else o.optBoolean("switch_back_restored"),
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
      // The person (or the system) is taking the connection down: the
      // engine's automatic connect is no longer followed or retried.
      autoMode = false
      // Before the dialer is retracted (in teardownEngine), as always.
      stopSchedulerPump()
    }
    // requestStop runs on the main thread, where the watch lives.
    stopNetworkWatch()
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
    // The follower (see AUTOMATIC CONNECT). It only queues a look on
    // the control thread, and only while an automatic connect is in
    // charge; it shares this executor, so a tick that is inside a slow
    // refresh delays it — the page's own vpnStatus polls do not wait
    // for it (pokeFollow).
    pump.scheduleWithFixedDelay({
      try { queueFollow() } catch (_: Throwable) {}
    }, FOLLOW_SECONDS, FOLLOW_SECONDS, TimeUnit.SECONDS)
  }

  private fun stopSchedulerPump() {
    // shutdownNow, not shutdown: requestStop() runs on the main thread
    // and must not block behind an in-flight tick that is inside a 15 s
    // network refresh. The engine's tick is safe to abandon — it drops
    // overlapping/late ticks by design.
    schedulerPump?.shutdownNow()
    schedulerPump = null
  }

  /**
   * Notification text for a connected tunnel; names no route when
   * [routeId] is null. While the engine's automatic connect is in
   * charge it is always null — the engine may change route by itself,
   * for a route that stopped carrying or for a faster one, and a
   * notification that names none is true before and after.
   */
  private fun noteActive(routeId: String?): String =
    if (routeId.isNullOrEmpty()) {
      getString(R.string.daal_vpn_note_active)
    } else {
      getString(R.string.daal_vpn_note_active_route, routeId)
    }

  /**
   * Notification text while nothing is connected behind the interface:
   * that the phone itself has no network, when the phone says so, else
   * that Daal is reconnecting.
   */
  private fun noteHolding(): String =
    getString(
      if (NetworkWatch.noNetwork(lastNetFacts)) {
        R.string.daal_vpn_note_waiting_for_network
      } else {
        R.string.daal_vpn_note_reconnecting
      },
    )

  private fun promoteToForeground(text: String) {
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
      .setContentTitle(getString(R.string.daal_vpn_title))
      .setContentText(text)
      // The no-network line is longer than one row.
      .setStyle(NotificationCompat.BigTextStyle().bigText(text))
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
      getString(R.string.daal_vpn_channel_name),
      NotificationManager.IMPORTANCE_LOW,
    )
    ch.description = getString(R.string.daal_vpn_channel_description)
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

    // How often the service looks at where the engine's automatic
    // connect is (it also looks whenever the page asks for vpnStatus).
    private const val FOLLOW_SECONDS = 10L

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
    @Volatile private var tunUp: Boolean = false

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

    /**
     * True while the engine's automatic connect is in charge: from an
     * automatic start until a stop or a start of a route picked by
     * hand. Written under lifecycleLock.
     */
    @Volatile private var autoMode: Boolean = false

    /** The service instance alive in this process, for [pokeFollow]. */
    @Volatile private var live: DaalVpnService? = null

    /** One follow at most is queued on the control thread. */
    private val followQueued = java.util.concurrent.atomic.AtomicBoolean(false)

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

    /**
     * The one thread the engine is told about the network on. Not
     * [control]: a connect blocked there for the length of a search
     * must not hold back "the phone has no network".
     */
    private val network: ExecutorService = Executors.newSingleThreadExecutor { r ->
      Thread(r, "daal-vpn-network").apply { isDaemon = true }
    }

    /** True while the service's network callback is registered. */
    @Volatile private var reportingNetwork: Boolean = false

    /** The facts the engine last accepted since the watch started. */
    @Volatile private var lastNetFacts: NetworkWatch.Facts? = null

    /** When a search was last started by the network coming back (elapsedRealtime). */
    @Volatile private var lastNetRetryAt: Long = 0L

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

    /** The engine's automatic connect is in charge of the connection. */
    @JvmStatic fun isAuto(): Boolean = autoMode

    /**
     * The service is up and is itself telling the engine about the
     * phone's network. The page must then not send its own, poorer
     * fact (it knows neither the kind nor the identity).
     */
    @JvmStatic fun isReportingNetwork(): Boolean = reportingNetwork

    /**
     * The TUN is held with no route behind it while an automatic
     * connect is in charge (see [SwitchPolicy.holding]): every other
     * app is cut off until a route is up or the person disconnects.
     */
    @JvmStatic fun isHolding(): Boolean = SwitchPolicy.holding(autoMode, tunUp, connected)

    /**
     * Any thread; returns at once. Called when the page asks for
     * vpnStatus: if the engine may have moved to another route by
     * itself, look now rather than at the next timer turn. The answer
     * the page gets is the one already known; the next one is current.
     */
    @JvmStatic fun pokeFollow() { live?.queueFollow() }
  }
}
