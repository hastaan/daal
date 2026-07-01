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
 *
 * On `ACTION_STOP` / `onRevoke` / `onDestroy`:
 *   1. DaalCoreBridge.clearRoute()
 *   2. DaalCoreBridge.clearTunFd()  (engine closes the fd)
 *   3. stopForeground + stopSelf.
 *
 * Ordering matters: setTunFd before setRoute, registerProtectCallback
 * before setTunFd, clearRoute before clearTunFd.
 */
class DaalVpnService : VpnService() {

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
    val pfd: ParcelFileDescriptor = Builder()
      .setSession("Daal")
      .setMtu(1500)
      .addAddress("10.20.30.40", 32)
      .addRoute("0.0.0.0", 0)
      .addRoute("::", 0)
      .addDnsServer("1.1.1.1")
      .addDnsServer("9.9.9.9")
      .establish()
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
    return true
  }

  private fun teardown() {
    if (!connected) return
    connected = false
    try { DaalCoreBridge.clearRoute() } catch (_: Throwable) {}
    try { DaalCoreBridge.clearTunFd() } catch (_: Throwable) {}
    DaalCoreBridge.protectImpl = null
    activeRouteId = null
    stopForeground(STOP_FOREGROUND_REMOVE)
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
    private const val TAG = "DaalVpnService"

    @Volatile private var connected: Boolean = false
    @Volatile private var activeRouteId: String? = null

    @JvmStatic fun isConnected(): Boolean = connected
    @JvmStatic fun currentRouteId(): String? = activeRouteId
  }
}
