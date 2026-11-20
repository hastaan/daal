package org.daal.desktop.platform

import android.app.Activity
import android.app.Application
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkInfo
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Bundle
import android.os.HandlerThread
import android.os.Process
import android.os.SystemClock
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.util.Log
import android.view.WindowManager
import java.lang.ref.WeakReference
import java.net.Inet4Address
import java.net.Inet6Address
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.daal.desktop.vpn.DaalVpnService
import org.daal.desktop.vpn.NetworkWatch

/**
 * The phone's side of the network test (specs/field-probe-v2.md) while
 * one runs. Daal is disconnected then, so DaalVpnService — which
 * normally tells the engine about the network — is not running.
 *
 * [hostFacts] answers what the engine needs at the start and cannot see
 * itself: the network's DNS servers (Go cannot use Android's resolver
 * for the record types the test asks), the Private DNS mode, whether a
 * VPN is up, whether there is a global IPv6 address, and whether the
 * system blocks this app's traffic ("Block connections without VPN").
 * The DNS server addresses go to the engine in memory only; nothing
 * here logs them.
 *
 * [start] then, for the length of the run:
 *  - keeps telling the engine about the network
 *    (`engine_network_facts`, decided by the same [NetworkWatch] the
 *    service uses), so a move to another network stops the test;
 *  - cancels the test (`engine_field_probe_cancel("vpn_active")`) the
 *    moment any VPN network appears — another app's VPN would carry the
 *    test's connections and make its result about that VPN's network.
 *    Daal's own tunnel coming up cancels it as `connecting` instead, so
 *    the person is not told another VPN turned on;
 *  - keeps the screen on (FLAG_KEEP_SCREEN_ON on Daal's window): the
 *    screen timing out would hide the page and stop the test;
 *  - cancels the test (`"backgrounded"`) when Daal's activity stops
 *    (home, another app, the power button), whatever the page does — a
 *    page that was left or unmounted no longer listens for that.
 *
 * [stop] undoes all of it. A run lasts four minutes at most, so the
 * watch stops itself after [MAX_WATCH_MS] whatever happens to the page.
 */
object FieldProbeWatch {
  private const val TAG = "DaalFieldProbe"

  /** The engine's hard stop is 4 minutes; a little more, then let go. */
  const val MAX_WATCH_MS = 6 * 60 * 1000L

  /** What [hostFacts] answers. */
  data class HostFacts(
    val dnsServers: List<String>,
    /** "off" | "auto" | "strict" | "unknown" */
    val privateDns: String,
    val vpnActive: Boolean,
    val ipv6Global: Boolean,
    val blocked: Boolean,
  )

  private val lock = Any()
  private var thread: HandlerThread? = null
  private var handler: Handler? = null
  private var engineCalls: ExecutorService? = null
  private var cm: ConnectivityManager? = null
  private var netCallback: ConnectivityManager.NetworkCallback? = null
  private var vpnCallback: ConnectivityManager.NetworkCallback? = null
  private var appContext: Context? = null
  /** Daal's activity while watching: the screen-on flag and its stop. */
  private var activityRef: WeakReference<Activity>? = null
  private var lifecycle: Application.ActivityLifecycleCallbacks? = null
  private val watch = NetworkWatch()
  private val flush = Runnable { flushNetwork() }
  private val expire = Runnable { stop() }

  private fun manager(context: Context): ConnectivityManager? = try {
    context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
  } catch (_: Throwable) {
    null
  }

  /**
   * Any thread. Reads only; registers nothing. (NetworkInfo is
   * deprecated, and it is still the one place a BLOCKED default network
   * shows without registering a callback.)
   */
  @Suppress("DEPRECATION")
  fun hostFacts(context: Context): HostFacts {
    val cm = manager(context)
      ?: return HostFacts(emptyList(), "unknown", vpnActive = false, ipv6Global = false, blocked = false)
    var dns = emptyList<String>()
    var privateDns = "unknown"
    var ipv6 = false
    var blocked = false
    try {
      val active = cm.activeNetwork
      val link = active?.let { cm.getLinkProperties(it) }
      if (link != null) {
        dns = link.dnsServers.mapNotNull { a -> a.hostAddress?.takeIf { it.isNotEmpty() } }
        privateDns = privateDnsMode(link)
        ipv6 = link.linkAddresses.any { la ->
          val a = la.address
          a is Inet6Address && !a.isLinkLocalAddress && !a.isSiteLocalAddress &&
            !a.isLoopbackAddress && !a.isAnyLocalAddress && !isUniqueLocal(a)
        }
      }
      // "Block connections without VPN" (always-on VPN with lockdown,
      // our own or another app's): the system reports this app's
      // default network as BLOCKED, or gives it none while one exists.
      val info: NetworkInfo? = cm.activeNetworkInfo
      blocked = info?.detailedState == NetworkInfo.DetailedState.BLOCKED
    } catch (t: Throwable) {
      Log.w(TAG, "host facts: ${t.javaClass.simpleName}")
    }
    return HostFacts(dns, privateDns, vpnActive(cm), ipv6, blocked)
  }

  private fun privateDnsMode(link: LinkProperties): String {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return "off"
    return try {
      when {
        !link.privateDnsServerName.isNullOrEmpty() -> "strict"
        link.isPrivateDnsActive -> "auto"
        else -> "off"
      }
    } catch (_: Throwable) {
      "unknown"
    }
  }

  /** fc00::/7 */
  private fun isUniqueLocal(a: Inet6Address): Boolean = (a.address[0].toInt() and 0xfe) == 0xfc

  /** Any VPN network up right now (ours or another app's). */
  @Suppress("DEPRECATION")
  private fun vpnActive(cm: ConnectivityManager): Boolean = try {
    cm.allNetworks.any { n ->
      cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }
  } catch (_: Throwable) {
    false
  }

  /** Any thread. Idempotent: a second start keeps the first watch. */
  fun start(activity: Activity) {
    val context: Context = activity.applicationContext
    synchronized(lock) {
      if (thread != null) {
        handler?.removeCallbacks(expire)
        handler?.postDelayed(expire, MAX_WATCH_MS)
        return
      }
      val cm = manager(context) ?: run {
        Log.w(TAG, "watch: no ConnectivityManager; the engine is not told about the network")
        return
      }
      // The screen stays on, and leaving Daal stops the test, for as
      // long as the watch is on (undone by stopLocked, also when a
      // registration below fails).
      watchActivity(activity)
      val t = HandlerThread("daal-fieldprobe").apply { start() }
      val h = Handler(t.looper)
      thread = t
      handler = h
      engineCalls = Executors.newSingleThreadExecutor()
      this.cm = cm
      appContext = context.applicationContext
      try {
        val active = cm.activeNetwork
        if (active != null) {
          val caps = try { cm.getNetworkCapabilities(active)?.let { capsOf(it) } } catch (_: Throwable) { null }
          val link = try { cm.getLinkProperties(active)?.let { linkOf(it) } } catch (_: Throwable) { null }
          watch.startDescribed(active.networkHandle, caps, link, now())?.let { send(it) }
        } else {
          watch.start(false, now())
          watch.due(now())?.let { send(it) }
        }
        later(watch.nextIn(now()))

        // The network the test goes out on: internet, and not a VPN —
        // the same request DaalVpnService makes, for the same reason.
        val wanted = NetworkRequest.Builder()
          .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
          .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
          override fun onAvailable(network: Network) {
            later(watch.available(network.networkHandle, now()))
          }
          override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            later(watch.capabilities(network.networkHandle, capsOf(caps), now()))
          }
          override fun onLinkPropertiesChanged(network: Network, link: LinkProperties) {
            later(watch.link(network.networkHandle, linkOf(link), now()))
          }
          override fun onLost(network: Network) {
            later(watch.lost(network.networkHandle, now()))
          }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
          cm.registerBestMatchingNetworkCallback(wanted, cb, h)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
          cm.registerNetworkCallback(wanted, cb, h)
        } else {
          cm.registerNetworkCallback(wanted, cb)
        }
        netCallback = cb

        // Any VPN at all. A VPN network is not "not VPN", so the
        // builder's default NOT_VPN capability has to be removed.
        val vpn = NetworkRequest.Builder()
          .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
          .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
          .build()
        val vcb = object : ConnectivityManager.NetworkCallback() {
          override fun onAvailable(network: Network) {
            // Daal's own tunnel is "connecting", not another VPN: the
            // engine would say so too, a moment later.
            val reason = if (isOwnVpn(cm, network)) "connecting" else "vpn_active"
            Log.i(TAG, "watch: a VPN came up (reason=$reason); stopping the test")
            cancelEngine(reason)
          }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
          cm.registerNetworkCallback(vpn, vcb, h)
        } else {
          cm.registerNetworkCallback(vpn, vcb)
        }
        vpnCallback = vcb
        h.postDelayed(expire, MAX_WATCH_MS)
        Log.i(TAG, "watch: on")
      } catch (t: Throwable) {
        // SecurityException without ACCESS_NETWORK_STATE; the system's
        // callback limit. The engine's own checks still stop the test
        // on a VPN or a moved socket; it just learns later.
        Log.w(TAG, "watch: could not register: ${t.javaClass.simpleName}")
        stopLocked()
      }
    }
  }

  /** Any thread. Idempotent. */
  fun stop() {
    synchronized(lock) { stopLocked() }
  }

  /** On the watch's thread. Is [network] the VPN Daal itself set up? */
  private fun isOwnVpn(cm: ConnectivityManager, network: Network): Boolean {
    if (DaalVpnService.isRunning()) return true
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false
    return try {
      cm.getNetworkCapabilities(network)?.ownerUid == Process.myUid()
    } catch (_: Throwable) {
      false
    }
  }

  /** One `engine_field_probe_cancel`, off the calling thread. */
  private fun cancelEngine(reason: String) {
    val ex = synchronized(lock) { engineCalls }
    val call = Runnable {
      val rc = try { DaalCoreBridge.fieldProbeCancel(reason) } catch (_: Throwable) { -1 }
      Log.i(TAG, "watch: cancel reason=$reason engine_rc=$rc")
    }
    try {
      if (ex != null) ex.execute(call) else Thread(call, "daal-fieldprobe-cancel").start()
    } catch (_: Throwable) {
      // Stopped meanwhile.
    }
  }

  /**
   * Under [lock]. The screen stays on while the test runs, and the test
   * stops when Daal's activity stops.
   */
  private fun watchActivity(activity: Activity) {
    activityRef = WeakReference(activity)
    activity.runOnUiThread {
      try {
        activity.window?.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
      } catch (_: Throwable) {}
    }
    val cb = object : Application.ActivityLifecycleCallbacks {
      override fun onActivityStopped(a: Activity) {
        if (a !== activityRef?.get()) return
        Log.i(TAG, "watch: Daal left the screen; stopping the test")
        cancelEngine("backgrounded")
      }
      override fun onActivityCreated(a: Activity, savedInstanceState: Bundle?) {}
      override fun onActivityStarted(a: Activity) {}
      override fun onActivityResumed(a: Activity) {}
      override fun onActivityPaused(a: Activity) {}
      override fun onActivitySaveInstanceState(a: Activity, outState: Bundle) {}
      override fun onActivityDestroyed(a: Activity) {}
    }
    try {
      activity.application.registerActivityLifecycleCallbacks(cb)
      lifecycle = cb
    } catch (t: Throwable) {
      Log.w(TAG, "watch: no activity callbacks: ${t.javaClass.simpleName}")
    }
  }

  /** Under [lock]. Undoes [watchActivity]. */
  private fun unwatchActivity() {
    val activity = activityRef?.get()
    activityRef = null
    val cb = lifecycle
    lifecycle = null
    if (activity == null) return
    if (cb != null) {
      try { activity.application.unregisterActivityLifecycleCallbacks(cb) } catch (_: Throwable) {}
    }
    activity.runOnUiThread {
      try {
        activity.window?.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
      } catch (_: Throwable) {}
    }
  }

  private fun stopLocked() {
    unwatchActivity()
    val cm = this.cm
    for (cb in listOfNotNull(netCallback, vpnCallback)) {
      try { cm?.unregisterNetworkCallback(cb) } catch (_: Throwable) {}
    }
    val wasOn = thread != null
    netCallback = null
    vpnCallback = null
    watch.stop()
    handler?.removeCallbacksAndMessages(null)
    handler = null
    thread?.quitSafely()
    thread = null
    engineCalls?.shutdown()
    engineCalls = null
    this.cm = null
    if (wasOn) Log.i(TAG, "watch: off")
  }

  private fun now() = SystemClock.elapsedRealtime()

  /** [delayMs] is what a [NetworkWatch] call answered. */
  private fun later(delayMs: Long?) {
    if (delayMs == null) return
    val h = synchronized(lock) { handler } ?: return
    h.removeCallbacks(flush)
    h.postDelayed(flush, delayMs)
  }

  /** On the watch's thread. */
  private fun flushNetwork() {
    watch.due(now())?.let { send(it) }
    later(watch.nextIn(now()))
  }

  /** One engine call, off the callback thread (it writes the engine's store). */
  private fun send(facts: NetworkWatch.Facts) {
    val ex = synchronized(lock) { engineCalls } ?: return
    try {
      ex.execute {
        val rc = try {
          DaalCoreBridge.networkFacts(facts.kind, facts.id, facts.validated, facts.metered)
        } catch (_: Throwable) {
          -1
        }
        // The kind and the flags; of the id only whether there is one.
        Log.i(
          TAG,
          "network: kind=${facts.kind} validated=${facts.validated} metered=${facts.metered} " +
            "id=${if (facts.id.isEmpty()) "none" else "set"} engine_rc=$rc",
        )
        later(watch.delivered(facts, rc >= 0, now()))
      }
    } catch (_: Throwable) {
      // Stopped meanwhile.
    }
  }

  // The two readings DaalVpnService makes (capsOf / linkOf there), so
  // the engine is told the same facts about the same network.

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

  private fun simOperator(): String = try {
    val ctx = appContext
    var tm = ctx?.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
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
}
