package org.daal.desktop.platform

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.webkit.WebView
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.ActivityResult
import app.tauri.Logger
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.daal.desktop.vpn.BACK_JS
import org.daal.desktop.vpn.DaalVpnService
import org.daal.desktop.vpn.backWasHandled

@InvokeArg
class VpnStartArgs {
  /**
   * The route to connect. ABSENT OR EMPTY = connect automatically: the
   * service asks the engine to pick a route, try it and move on.
   */
  var routeId: String? = null
}

/**
 * Tauri Mobile plugin entry point on Android. Mirrors the Rust
 * `commands::vpn_*` surface declared in src/commands.rs.
 *
 *   vpnStart(routeId): prepares VpnService (system consent dialog
 *       if needed) and starts DaalVpnService with the chosen route —
 *       or, with no routeId, lets the engine choose (automatic
 *       connect). The consent flow is the same either way.
 *   vpnStop():          stops DaalVpnService (engine_clear_tun_fd).
 *   vpnStatus():        thin status read; the engine itself does
 *                       not currently expose a "connected" boolean,
 *                       so we mirror the in-Kotlin lifecycle flag
 *                       on DaalCoreBridge.
 *
 * The plugin does NOT itself touch libdaalcore.so — that goes through
 * DaalCoreBridge, which is the only JNI surface in this module so the
 * native-symbol contract stays explicit.
 */
@TauriPlugin
class DaalPlatformPlugin(private val activity: Activity) : Plugin(activity) {

  /**
   * The system Back, answered by the app itself.
   *
   * The UI keeps one back stack in JS (client-ui/src/lib/backStack.ts)
   * and publishes `window.__daalBack()`: it runs the topmost handler
   * (close a sheet, go back one page) and returns true, or returns
   * false when nothing is open. Going through the web view's history
   * instead does not hold: Chromium skips a history entry the page
   * added without a touch, so the second Back in a row left the app
   * (seen on the phone 2026-11-19).
   *
   * This callback is added after the web view's own, so it is asked
   * first. When the page has nothing to close (or does not answer),
   * it steps aside and Back goes on to the default: leave the app.
   */
  override fun load(webView: WebView) {
    super.load(webView)
    val host = activity as? ComponentActivity ?: return
    val callback = object : OnBackPressedCallback(true) {
      override fun handleOnBackPressed() {
        val self = this
        try {
          webView.evaluateJavascript(BACK_JS) { result ->
            if (!backWasHandled(result)) {
              self.isEnabled = false
              try {
                host.onBackPressedDispatcher.onBackPressed()
              } finally {
                self.isEnabled = true
              }
            }
          }
        } catch (t: Throwable) {
          Logger.error("DaalPlatformPlugin back failed: ${t.message}")
          self.isEnabled = false
          try {
            host.onBackPressedDispatcher.onBackPressed()
          } finally {
            self.isEnabled = true
          }
        }
      }
    }
    host.onBackPressedDispatcher.addCallback(host, callback)
  }

  private var pendingStartArgs: VpnStartArgs? = null
  private var pendingInvoke: Invoke? = null

  @Command
  fun vpnStart(invoke: Invoke) {
    try {
      val args = invoke.parseArgs(VpnStartArgs::class.java)
      val consent = VpnService.prepare(activity)
      if (consent != null) {
        // User has not yet granted VPN consent. Capture the invoke
        // and route through ActivityCallback so we can resume once
        // the system Activity returns.
        pendingStartArgs = args
        pendingInvoke = invoke
        startActivityForResult(invoke, consent, "vpnConsentResult")
        return
      }
      startService(args.routeId)
      val response = JSObject().apply {
        put("applied", true)
        put("platform", "android")
        put("requires_consent", false)
      }
      invoke.resolve(response)
    } catch (t: Throwable) {
      Logger.error("DaalPlatformPlugin.vpnStart failed: ${t.message}")
      invoke.reject(t.message ?: "vpnStart failed")
    }
  }

  @ActivityCallback
  fun vpnConsentResult(invoke: Invoke, result: ActivityResult) {
    val args = pendingStartArgs ?: run {
      invoke.reject("no pending start args")
      return
    }
    pendingStartArgs = null
    pendingInvoke = null
    if (result.resultCode != Activity.RESULT_OK) {
      invoke.reject("VPN consent denied")
      return
    }
    try {
      startService(args.routeId)
      val response = JSObject().apply {
        put("applied", true)
        put("platform", "android")
        put("requires_consent", false)
      }
      invoke.resolve(response)
    } catch (t: Throwable) {
      Logger.error("DaalPlatformPlugin.vpnStart (after consent) failed: ${t.message}")
      invoke.reject(t.message ?: "vpnStart post-consent failed")
    }
  }

  @Command
  fun vpnStop(invoke: Invoke) {
    try {
      val intent = Intent(activity, DaalVpnService::class.java).apply {
        action = DaalVpnService.ACTION_STOP
      }
      activity.startService(intent)
      val response = JSObject().apply {
        put("applied", true)
        put("platform", "android")
      }
      invoke.resolve(response)
    } catch (t: Throwable) {
      Logger.error("DaalPlatformPlugin.vpnStop failed: ${t.message}")
      invoke.reject(t.message ?: "vpnStop failed")
    }
  }

  @Command
  fun vpnStatus(invoke: Invoke) {
    // While the engine's automatic connect is in charge it may have
    // moved to another route by itself; have the service look.
    DaalVpnService.pokeFollow()
    val response = JSObject().apply {
      put("connected", DaalVpnService.isConnected())
      // The route actually running, as the service last learned it from
      // the engine — not necessarily the one that was asked for.
      put("route_id", DaalVpnService.currentRouteId())
      put("platform", "android")
      put("auto", DaalVpnService.isAuto())
      // The VPN interface is up with nothing behind it (the engine ran
      // out of routes; the service is retrying): the page says so and
      // offers Disconnect.
      put("holding", DaalVpnService.isHolding())
      // The service is up and tells the engine about the phone's
      // network itself (from a start until the stop, connected or
      // not): the page keeps its own network_changed call to itself.
      put("running", DaalVpnService.isReportingNetwork())
      // The last switch that did not take (see SwitchPolicy.SwitchNote):
      // which route was asked for, which one the service stayed on, and
      // a closed code for why. Absent when there is nothing to say.
      DaalVpnService.lastSwitchNote()?.let { n ->
        put(
          "last_switch",
          JSObject().apply {
            put("route_id", n.requestedRouteId)
            put("kept_route_id", n.keptRouteId)
            put("outcome", n.outcome)
            put("reason", n.reason)
            put("auto", n.auto)
          },
        )
      }
    }
    invoke.resolve(response)
  }

  /** [routeId] null or empty = automatic connect (no extra is sent). */
  private fun startService(routeId: String?) {
    val intent = Intent(activity, DaalVpnService::class.java).apply {
      action = DaalVpnService.ACTION_START
      if (!routeId.isNullOrBlank()) putExtra(DaalVpnService.EXTRA_ROUTE_ID, routeId)
    }
    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
      activity.startForegroundService(intent)
    } else {
      activity.startService(intent)
    }
  }
}
