package org.daal.desktop.platform

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import androidx.annotation.Keep
import app.tauri.Logger
import org.daal.desktop.vpn.FLAG_LAUNCHED_FROM_HISTORY
import org.daal.desktop.vpn.IntentFacts
import org.daal.desktop.vpn.MAX_OPENED_BYTES
import org.daal.desktop.vpn.Opened
import org.daal.desktop.vpn.decideOpened
import org.daal.desktop.vpn.lastSegment
import org.daal.desktop.vpn.stagedOpenedName
import java.io.File
import java.io.InputStream
import java.security.SecureRandom

/**
 * "Open with Daal" and "Share to Daal" (spec G.1, X-13).
 *
 * The intent filters (tools/patch-android-manifest.sh) send Daal a file
 * opened from a messenger or file manager (VIEW), a file shared to it
 * (SEND with EXTRA_STREAM) or a text shared to it (SEND text/plain).
 * DaalPlatformPlugin hands each intent here: the launch intent from
 * `load`, a later one from `onNewIntent` (the activity is singleTask,
 * so a second file while Daal runs arrives there).
 *
 * The rules for what is taken live in vpn/OpenedIntent.kt (no Android
 * types, tested on a plain JVM). Only the newest one is held: a newer
 * share replaces one the page has not taken yet.
 *
 * NOTHING IS IMPORTED HERE. The Rust command `take_opened_file`
 * (src-tauri/src/opened.rs) calls [take] to copy the held file into the
 * app's staging directory and gives the page that path; the page shows
 * the file and the person decides. When one arrives while the page is
 * up, [nativeArrived] tells Rust, which stages it the same way and
 * fires the `daal://opened-file` event.
 */
@Keep
object OpenedFiles {
  /** Set by DaalPlatformPlugin.load. */
  @Volatile
  @JvmStatic
  var context: Context? = null

  private val lock = Any()
  private var pending: Opened? = null

  /** Marks the activity's launch intent as handed over, so a reload of the page does not offer it twice. */
  private const val EXTRA_TAKEN = "org.daal.desktop.OPENED_TAKEN"

  init {
    try {
      System.loadLibrary("daal_desktop_tauri_lib")
    } catch (_: Throwable) {
      // Already loaded by the activity, or missing (then nativeArrived
      // throws and notifyArrived ignores it).
    }
  }

  /** Hold what [intent] hands Daal, if anything. True when something was held. */
  fun offer(ctx: Context, intent: Intent?): Boolean {
    if (intent == null) return false
    return try {
      if (intent.getBooleanExtra(EXTRA_TAKEN, false)) return false
      val opened = decideOpened(factsOf(intent), ctx.packageName) ?: return false
      intent.putExtra(EXTRA_TAKEN, true)
      synchronized(lock) { pending = opened }
      true
    } catch (t: Throwable) {
      Logger.error("OpenedFiles.offer failed: ${t.message}")
      false
    }
  }

  private fun factsOf(intent: Intent): IntentFacts {
    val stream: Uri? = try {
      if (Build.VERSION.SDK_INT >= 33) {
        intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
      } else {
        @Suppress("DEPRECATION")
        intent.getParcelableExtra<android.os.Parcelable>(Intent.EXTRA_STREAM) as? Uri
      }
    } catch (_: Throwable) {
      null
    }
    val text = try {
      intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
    } catch (_: Throwable) {
      null
    }
    return IntentFacts(
      action = intent.action,
      data = intent.dataString,
      stream = stream?.toString(),
      text = text,
      flags = intent.flags and FLAG_LAUNCHED_FROM_HISTORY,
    )
  }

  /** Tell Rust one arrived while Daal runs. Safe to call when the native side is missing. */
  fun notifyArrived() {
    try {
      nativeArrived()
    } catch (t: Throwable) {
      Logger.error("OpenedFiles.nativeArrived failed: ${t.message}")
    }
  }

  /** Implemented in src-tauri/src/opened.rs. */
  external fun nativeArrived()

  /** True when a file or text is waiting for the page. */
  @Keep
  @JvmStatic
  fun hasPending(): Boolean = synchronized(lock) { pending != null }

  /**
   * Copy the held file (or write the held text) into [destDir] and
   * return its path; null when nothing is held or it could not be read.
   * Called from Rust via JNI, signature (String)String, off the main
   * thread (it reads another app's provider). Returns each one once.
   */
  @Keep
  @JvmStatic
  fun take(destDir: String): String? {
    val opened = synchronized(lock) { pending.also { pending = null } } ?: return null
    val ctx = context ?: return null
    return try {
      val dir = File(destDir)
      if (!dir.isDirectory && !dir.mkdirs()) return null
      when (opened) {
        is Opened.Text -> {
          val dest = File(dir, stagedOpenedName(opened, null, randomTag()))
          if (!dest.createNewFile()) return null
          dest.writeText(opened.text, Charsets.UTF_8)
          dest.absolutePath
        }
        is Opened.File -> {
          val uri = Uri.parse(opened.uri)
          val name = displayName(ctx, uri) ?: lastSegment(opened.uri)
          val dest = File(dir, stagedOpenedName(opened, name, randomTag()))
          val input = ctx.contentResolver.openInputStream(uri) ?: return null
          if (copyCapped(input, dest)) dest.absolutePath else null
        }
      }
    } catch (t: Throwable) {
      Logger.error("OpenedFiles.take failed: ${t.message}")
      null
    }
  }

  private fun displayName(ctx: Context, uri: Uri): String? = try {
    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
      if (c.moveToFirst() && !c.isNull(0)) c.getString(0) else null
    }
  } catch (_: Throwable) {
    null
  }

  /** Copy at most MAX_OPENED_BYTES; a bigger stream is not a Daal file and leaves nothing behind. */
  private fun copyCapped(input: InputStream, dest: File): Boolean {
    if (!dest.createNewFile()) return false
    var ok = false
    try {
      input.use { src ->
        dest.outputStream().use { sink ->
          val buf = ByteArray(64 * 1024)
          var total = 0L
          while (true) {
            val n = src.read(buf)
            if (n < 0) break
            total += n
            if (total > MAX_OPENED_BYTES) {
              Logger.error("OpenedFiles: the shared file is larger than $MAX_OPENED_BYTES bytes; not taken")
              return false
            }
            sink.write(buf, 0, n)
          }
        }
      }
      ok = true
      return true
    } finally {
      if (!ok) dest.delete()
    }
  }

  private fun randomTag(): String {
    val b = ByteArray(8)
    SecureRandom().nextBytes(b)
    return b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
  }
}
