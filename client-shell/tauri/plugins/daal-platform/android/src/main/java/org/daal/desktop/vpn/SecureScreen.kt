package org.daal.desktop.vpn

// Whether the app's window may be captured (screenshots, screen
// recording, the recent-apps thumbnail), kept free of Android types so it
// runs in the plain-JVM tests (tools/test-android-jvm.sh). Used by
// platform/DaalPlatformPlugin.secureScreen (PB-20).
//
// The page asks for it while the recovery-words screen, the type-the-
// words-back screen or the restore words-entry screen is shown, and
// lets go when none is. FLAG_SECURE is a property of the window, not of
// the process: a new activity window starts without it, so an app that
// was killed while it was set starts clear. The plugin also clears it
// whenever it loads, in case a window outlived the page that asked.

/** What to do to the window's FLAG_SECURE. */
enum class SecureFlagChange { ADD, CLEAR, NONE }

/**
 * The flag as last applied to the window, and the change one request
 * needs. Never ADD twice or CLEAR what is not set: each request is
 * answered from what the window has, not from a count, so a lost "off"
 * cannot leave the flag stuck behind a counter (the page re-sends its
 * wish on every mount and unmount).
 */
class SecureScreen {
  var applied: Boolean = false
    private set

  fun request(on: Boolean): SecureFlagChange {
    val change = when {
      on && !applied -> SecureFlagChange.ADD
      !on && applied -> SecureFlagChange.CLEAR
      else -> SecureFlagChange.NONE
    }
    applied = on
    return change
  }

  /** A (re)loaded page starts with nothing asked: clear, always. */
  fun atLoad(): SecureFlagChange {
    applied = false
    return SecureFlagChange.CLEAR
  }
}
