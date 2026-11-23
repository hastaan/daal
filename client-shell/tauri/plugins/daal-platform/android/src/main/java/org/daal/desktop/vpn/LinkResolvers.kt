package org.daal.desktop.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.daal.desktop.platform.DaalCoreBridge
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * The phone's DNS servers to the engine (`engine_set_link_resolvers`),
 * with or without the VPN service.
 *
 * WHY. Go cannot read the DNS servers on Android, and the update
 * ladder's DNS reader asks only the network's own resolver. Until this
 * existed only DaalVpnService told the engine, from its network
 * callback, so the check of the backup update routes and the person's
 * update button (both run with no connection, so with no service) found
 * "no resolver" on every phone.
 *
 * TWO REPORTERS, one process (the service has no process of its own):
 *  - the app: [startAppScope] from the plugin's load, [stopAppScope] at
 *    its destroy (counted: the last owner unregisters). A ConnectivityManager callback for the best network
 *    that has internet and is NOT a VPN (NET_CAPABILITY_NOT_VPN), so
 *    the servers are never the tunnel's own;
 *  - DaalVpnService, from its own callback for the same request, while
 *    it runs ([link] / [lost] / [detach] with [SERVICE]).
 * Which list the engine is told is [ResolverGate] (pure, unit tested;
 * the rule is written there): the network that spoke last wins, a
 * "lost" for a network that is not the current one changes nothing,
 * "[]" only when no network is left, the same list once.
 *
 * Every engine call is made on one thread of this object's own, in the
 * order the gate answered, so the two reporters' sends cannot overtake
 * each other. A send the engine did not take (the library is not loaded
 * yet: the call returns -1 or throws) is tried again at the next event,
 * at the next resume of the app ([retryPending]), and a few times on a
 * short backoff so a phone on a quiet network is not left without.
 *
 * Never logs an address: only how many, which reporter, and the
 * engine's code.
 */
object LinkResolvers {
  const val APP = "app"
  const val SERVICE = "service"

  private const val TAG = "DaalVpnService"
  private const val RC_THREW = -3
  private const val MAX_SENT = 8
  private val RETRY_MS = longArrayOf(1_000L, 3_000L, 10_000L, 30_000L, 60_000L)

  private val gate = ResolverGate()

  private val thread: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
    Thread(r, "daal-link-resolvers").apply { isDaemon = true }
  }

  /** [thread] only. */
  private var retry: ScheduledFuture<*>? = null
  private var retries = 0

  /** Main thread only. */
  private var appCallback: ConnectivityManager.NetworkCallback? = null

  /**
   * Main thread only. How many plugin instances (one per activity) hold
   * the app-scope callback. A new activity can load before the old one's
   * onDestroy runs (finish, then a quick relaunch); the callback is
   * process-wide, so only the last owner to stop unregisters it.
   */
  private var appOwners = 0
  private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

  /** The link's DNS server addresses (never logged). */
  fun dnsOf(link: LinkProperties): List<String> = try {
    link.dnsServers.mapNotNull { a -> a.hostAddress?.takeIf { it.isNotEmpty() } }
  } catch (_: Throwable) {
    emptyList()
  }

  /**
   * Both reporters follow one network at a time from Android 12 on
   * (registerBestMatchingNetworkCallback): see [ResolverGate.link].
   */
  private val singleNetwork: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

  /** Any thread. [reporter]'s network [network] has these link properties. */
  fun link(reporter: String, network: Network, link: LinkProperties) {
    val servers = dnsOf(link)
    val handle = network.networkHandle
    val single = singleNetwork
    post(reporter) { gate.link(reporter, handle, servers, single) }
  }

  /** Any thread. [reporter] heard that [network] is gone. */
  fun lost(reporter: String, network: Network) {
    val handle = network.networkHandle
    post(reporter) { gate.lost(reporter, handle) }
  }

  /** Any thread. [reporter] no longer listens. Sends nothing. */
  fun detach(reporter: String) {
    try {
      thread.execute { gate.detach(reporter) }
    } catch (_: Throwable) {}
  }

  /** Any thread. Send again what the engine has not taken yet, if anything. */
  fun retryPending() {
    post("retry") { gate.pending() }
  }

  private fun post(from: String, decide: () -> List<String>?) {
    try {
      thread.execute {
        val servers = try { decide() } catch (_: Throwable) { null } ?: return@execute
        send(from, servers)
      }
    } catch (_: Throwable) {}
  }

  /** [thread] only. One engine call. */
  private fun send(from: String, servers: List<String>) {
    val body = org.json.JSONArray(servers.take(MAX_SENT)).toString()
    val rc = try {
      DaalCoreBridge.setLinkResolvers(body)
    } catch (_: Throwable) {
      RC_THREW
    }
    gate.delivered(servers, rc >= 0)
    Log.i(TAG, "network: resolvers n=${servers.size} from=$from engine_rc=$rc")
    retry?.cancel(false)
    retry = null
    if (rc >= 0) {
      retries = 0
      return
    }
    if (retries >= RETRY_MS.size) return
    val delay = RETRY_MS[retries++]
    retry = try {
      thread.schedule(
        Runnable {
          retry = null
          val again = gate.pending()
          if (again != null) send("retry", again)
        },
        delay,
        TimeUnit.MILLISECONDS,
      )
    } catch (_: Throwable) {
      null
    }
  }

  /**
   * Main thread. Idempotent. Listen from app scope; the first report
   * follows at once (Android calls a new callback back with the network
   * it already has). Nothing is sent when there is no network at all:
   * the engine has no resolver then either.
   */
  fun startAppScope(context: Context) {
    appOwners++
    if (appCallback != null) return
    val cm = try {
      context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    } catch (_: Throwable) {
      null
    }
    if (cm == null) {
      Log.w(TAG, "network: no ConnectivityManager; resolvers not reported from the app")
      return
    }
    val cb = object : ConnectivityManager.NetworkCallback() {
      override fun onAvailable(network: Network) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
          // Before Android 8 the link properties are not promised to
          // follow by themselves; ask once.
          try { cm.getLinkProperties(network)?.let { link(APP, network, it) } } catch (_: Throwable) {}
        }
      }

      override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
        link(APP, network, lp)
      }

      override fun onLost(network: Network) {
        lost(APP, network)
      }
    }
    try {
      // The same request as DaalVpnService's (see startNetworkWatch
      // there for why it is not the default-network callback).
      val wanted = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        cm.registerBestMatchingNetworkCallback(wanted, cb, mainHandler)
      } else {
        cm.registerNetworkCallback(wanted, cb)
      }
      appCallback = cb
      Log.i(TAG, "network: resolvers watched from the app")
    } catch (t: Throwable) {
      // SecurityException without ACCESS_NETWORK_STATE; RuntimeException
      // past the system's callback limit.
      Log.w(TAG, "network: could not watch resolvers from the app: ${t.javaClass.simpleName}")
    }
  }

  /**
   * Main thread. One call per [startAppScope]; the callback is
   * unregistered when the last owner stops. Sends nothing: the engine
   * keeps its list.
   */
  fun stopAppScope(context: Context) {
    if (appOwners > 0) appOwners--
    if (appOwners > 0) return
    val cb = appCallback ?: return
    appCallback = null
    try {
      (context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager)
        ?.unregisterNetworkCallback(cb)
    } catch (_: Throwable) {}
    detach(APP)
    Log.i(TAG, "network: resolvers no longer watched from the app")
  }
}
