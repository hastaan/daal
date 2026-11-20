package org.daal.desktop.platform

import android.app.Activity
import androidx.activity.result.ActivityResult
import androidx.activity.result.IntentSenderRequest
import app.tauri.Logger
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.Scope

@InvokeArg
class GoogleAuthorizeArgs {
  /** The OAuth scopes to ask for. Only the two Apps Script ones are accepted. */
  var scopes: List<String> = emptyList()
}

/**
 * Optional add-ons, Google update channel, Path A
 * (docs/optional-addons-plan.md §3.3 and §3.5, item G3).
 *
 * One call, `googleAuthorize(scopes)`, returns a one-shot OAuth access
 * token from Play services' authorization client. Google no longer
 * supports custom URI schemes on Android and has deprecated loopback
 * for Android clients, so this is the supported route: no client
 * secret, no redirect. Play services matches the app to the owner's
 * "Android" OAuth client by package name and the SHA-1 of the release
 * signing certificate; a build signed with another key (a debug build)
 * gets DEVELOPER_ERROR, reported as E_GOOGLE_NOT_CONFIGURED, and the
 * publisher uses the by-hand path.
 *
 * The token is handed to Rust once (mobile.rs, then
 * daal_wizard::addon_google::sign_in), used for four Apps Script API
 * calls and revoked. Nothing here keeps it, logs it or writes it down.
 *
 * Every rejection message starts with a stable code the wizard passes
 * through: E_GOOGLE_NOT_CONFIGURED, E_GOOGLE_NO_PLAY_SERVICES,
 * E_GOOGLE_SIGN_IN_CANCELLED, E_GOOGLE_UNAUTHORIZED.
 */
@TauriPlugin
class GoogleAuthPlugin(private val activity: Activity) : Plugin(activity) {

  private val allowedScopes = setOf(
    "https://www.googleapis.com/auth/script.projects",
    "https://www.googleapis.com/auth/script.deployments",
  )

  @Command
  fun googleAuthorize(invoke: Invoke) {
    val scopes: List<String>
    try {
      scopes = invoke.parseArgs(GoogleAuthorizeArgs::class.java).scopes
    } catch (t: Throwable) {
      invoke.reject("E_GOOGLE_UNAUTHORIZED: bad request")
      return
    }
    if (scopes.isEmpty() || !allowedScopes.containsAll(scopes)) {
      invoke.reject("E_GOOGLE_UNAUTHORIZED: only the Apps Script scopes may be asked for")
      return
    }
    val availability = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(activity)
    if (availability != ConnectionResult.SUCCESS) {
      invoke.reject("E_GOOGLE_NO_PLAY_SERVICES: this phone has no Google Play services; add the script by hand")
      return
    }
    val request = AuthorizationRequest.builder()
      .setRequestedScopes(scopes.map { Scope(it) })
      .build()
    try {
      Identity.getAuthorizationClient(activity)
        .authorize(request)
        .addOnSuccessListener { result: AuthorizationResult ->
          val pending = result.pendingIntent
          if (result.hasResolution() && pending != null) {
            // Google's own consent sheet (account choice, the
            // "unverified app" warning, the two permissions).
            try {
              startIntentSenderForResult(
                invoke,
                IntentSenderRequest.Builder(pending.intentSender).build(),
                "googleAuthorizeResult",
              )
            } catch (t: Throwable) {
              invoke.reject("E_GOOGLE_UNAUTHORIZED: could not show Google's sign-in")
            }
          } else {
            resolveToken(invoke, result)
          }
        }
        .addOnFailureListener { e -> invoke.reject(messageFor(e)) }
    } catch (t: Throwable) {
      invoke.reject(messageFor(t))
    }
  }

  @ActivityCallback
  fun googleAuthorizeResult(invoke: Invoke, result: ActivityResult) {
    if (result.resultCode != Activity.RESULT_OK || result.data == null) {
      invoke.reject("E_GOOGLE_SIGN_IN_CANCELLED: the Google sign-in was closed")
      return
    }
    try {
      val r = Identity.getAuthorizationClient(activity).getAuthorizationResultFromIntent(result.data)
      resolveToken(invoke, r)
    } catch (t: Throwable) {
      invoke.reject(messageFor(t))
    }
  }

  private fun resolveToken(invoke: Invoke, result: AuthorizationResult) {
    val token = result.accessToken
    if (token.isNullOrEmpty()) {
      invoke.reject("E_GOOGLE_UNAUTHORIZED: Google gave no access")
      return
    }
    invoke.resolve(JSObject().apply { put("accessToken", token) })
  }

  /** A stable code for a failure; never the token, never account details. */
  private fun messageFor(t: Throwable): String {
    val code = (t as? ApiException)?.statusCode
    Logger.error("GoogleAuthPlugin: authorization failed, status ${code ?: "-"}")
    return when (code) {
      CommonStatusCodes.DEVELOPER_ERROR ->
        "E_GOOGLE_NOT_CONFIGURED: this build is not registered with Google; add the script by hand"
      CommonStatusCodes.CANCELED ->
        "E_GOOGLE_SIGN_IN_CANCELLED: the Google sign-in was closed"
      CommonStatusCodes.NETWORK_ERROR ->
        "E_GOOGLE_UNAUTHORIZED: Google could not be reached"
      else -> "E_GOOGLE_UNAUTHORIZED: Google refused the sign-in"
    }
  }
}
