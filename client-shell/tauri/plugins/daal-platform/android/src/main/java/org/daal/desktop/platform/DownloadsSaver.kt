package org.daal.desktop.platform

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.provider.MediaStore
import androidx.annotation.Keep
import org.daal.desktop.vpn.savedName
import java.io.File

/**
 * Copy a staged file into the public Downloads collection and say the
 * name it was stored under (PB-3).
 *
 * MediaStore keeps the requested DISPLAY_NAME only when no file of that
 * name is there; otherwise it stores a de-duplicated one ("x (1).y").
 * The older MainActivity.saveToDownloads (written by
 * tools/patch-android-mainactivity.sh) answered only true/false, so the
 * screen named the file it had asked for. This one reads the stored
 * name back. Called from Rust via JNI (src-tauri/src/lib.rs,
 * `save_path_to_downloads`), signature (String,String)String; null =
 * not saved (nothing is left half-written: the pending entry is
 * deleted).
 *
 * The application context is set by DaalPlatformPlugin.load.
 */
@Keep
object DownloadsSaver {
  @Volatile
  @JvmStatic
  var context: Context? = null

  @Keep
  @JvmStatic
  fun save(path: String, displayName: String): String? {
    val ctx = context ?: return null
    if (Build.VERSION.SDK_INT < 29) return null
    val resolver = ctx.contentResolver
    return try {
      val values = ContentValues().apply {
        put(MediaStore.Downloads.DISPLAY_NAME, displayName)
        put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
        put(MediaStore.Downloads.IS_PENDING, 1)
      }
      val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
      val uri = resolver.insert(collection, values) ?: return null
      try {
        val out = resolver.openOutputStream(uri) ?: throw java.io.IOException("no output stream")
        out.use { sink -> File(path).inputStream().use { it.copyTo(sink) } }
        values.clear()
        values.put(MediaStore.Downloads.IS_PENDING, 0)
        resolver.update(uri, values, null, null)
      } catch (t: Throwable) {
        try {
          resolver.delete(uri, null, null)
        } catch (_: Throwable) {
        }
        return null
      }
      val stored = try {
        resolver.query(uri, arrayOf(MediaStore.Downloads.DISPLAY_NAME), null, null, null)?.use { c ->
          if (c.moveToFirst()) c.getString(0) else null
        }
      } catch (_: Throwable) {
        null
      }
      savedName(displayName, stored)
    } catch (_: Throwable) {
      null
    }
  }
}
