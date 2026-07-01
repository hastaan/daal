package org.daal.desktop.platform

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.ActivityResult
import app.tauri.Logger
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.daal.desktop.vpn.DaalVpnService

@InvokeArg
class VpnStartArgs {
  lateinit var routeId: String
}

/**
 * Tauri Mobile plugin entry point on Android. Mirrors the Rust
 * `commands::vpn_*` surface declared in src/commands.rs.
 *
 *   vpnStart(routeId): prepares VpnService (system consent dialog
 *       if needed) and starts DaalVpnService with the chosen route.
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
      invoke.reject(t.message ?: "vpnStop failed")
    }
  }

  @Command
  fun vpnStatus(invoke: Invoke) {
    val response = JSObject().apply {
      put("connected", DaalVpnService.isConnected())
      put("route_id", DaalVpnService.currentRouteId())
      put("platform", "android")
    }
    invoke.resolve(response)
  }

  private fun startService(routeId: String) {
    val intent = Intent(activity, DaalVpnService::class.java).apply {
      action = DaalVpnService.ACTION_START
      putExtra(DaalVpnService.EXTRA_ROUTE_ID, routeId)
    }
    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
      activity.startForegroundService(intent)
    } else {
      activity.startService(intent)
    }
  }
}
