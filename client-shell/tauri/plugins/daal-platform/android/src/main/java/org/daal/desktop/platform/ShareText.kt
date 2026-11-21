package org.daal.desktop.platform

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.annotation.Keep
import app.tauri.Logger
import java.lang.ref.WeakReference

/**
 * The Android share sheet with plain text (spec G.2): "Send address"
 * on the recipient's My Daal address. Called from Rust via JNI
 * (src-tauri/src/opened.rs, `share_text`), signature
 * (String,String)Z; false = the sheet could not be opened, and the page
 * falls back to Copy.
 *
 * The activity and the application context are set by
 * DaalPlatformPlugin.load. The sheet is started from the activity when
 * there is one, so it opens over Daal in Daal's own task.
 */
@Keep
object ShareText {
  /** The longest text handed to the sheet; a Daal address is ~80 characters, a pasted file tens of KB. */
  private const val MAX_CHARS = 200_000

  @Volatile
  @JvmStatic
  var context: Context? = null

  @Volatile
  private var activityRef: WeakReference<Activity>? = null

  fun setActivity(activity: Activity) {
    activityRef = WeakReference(activity)
  }

  @Keep
  @JvmStatic
  fun share(text: String, title: String?): Boolean {
    if (text.isEmpty() || text.length > MAX_CHARS) return false
    val activity = activityRef?.get()?.takeUnless { it.isFinishing }
    val ctx: Context = activity ?: context ?: return false
    return try {
      val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
      }
      val chooser = Intent.createChooser(send, title?.takeIf { it.isNotBlank() })
      // Started straight from the calling thread, as MainActivity.shareFile
      // does, so a failure is answered with false instead of lost.
      if (activity == null) chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      ctx.startActivity(chooser)
      true
    } catch (t: Throwable) {
      Logger.error("ShareText.share failed: ${t.message}")
      false
    }
  }
}
