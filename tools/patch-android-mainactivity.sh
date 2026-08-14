#!/usr/bin/env bash
# tools/patch-android-mainactivity.sh — restores Daal's custom
# MainActivity.kt into the Tauri-generated Android project.
#
# `tauri android init` regenerates a vanilla MainActivity.kt that only
# calls enableEdgeToEdge(). Daal's shell needs two additions the Rust
# side depends on (client-shell/tauri/src-tauri/src/lib.rs):
#
#   - a static `instance` holder set in onCreate, and
#   - a static `shareFile(path, mime, title)` invoked over JNI to export
#     a relay pack .sbp via the system share sheet.
#
# Without this patch the "Send relay pack" button throws
# `NoSuchMethodError: MainActivity.shareFile`. Because
# src-tauri/gen/android is gitignored and regenerated between sessions,
# this script is the durable source of truth — run it after
# `tauri android init`, before `tauri android build`.
#
# Idempotent: rewrites the file to the canonical content every run.

set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MAIN_ACTIVITY="${MAIN_ACTIVITY:-$ROOT/client-shell/tauri/src-tauri/gen/android/app/src/main/java/org/daal/desktop/MainActivity.kt}"

if [ ! -d "$(dirname "$MAIN_ACTIVITY")" ]; then
  echo "FATAL: $(dirname "$MAIN_ACTIVITY") not found (run \`tauri android init\` first)" >&2
  exit 1
fi

cat > "$MAIN_ACTIVITY" <<'KOTLIN'
package org.daal.desktop

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.core.content.FileProvider
import java.io.File

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    instance = this
  }

  override fun onDestroy() {
    if (instance === this) instance = null
    super.onDestroy()
  }

  companion object {
    // Set on create so the JNI-invoked static shareFile() below can
    // reach a live Context to start the share chooser from. The Rust
    // side (client-shell/tauri/src-tauri/src/lib.rs) calls this static
    // method to export the relay pack .sbp via the system share sheet.
    @JvmStatic
    var instance: MainActivity? = null

    // shareFile(path, mime, title): grant a content:// URI over the
    // app FileProvider and launch an ACTION_SEND chooser. Called from
    // Rust via JNI (signature (String,String,String)V). Throws (as a
    // Java exception surfaced to the Rust caller) if no Activity is
    // live or the file cannot be shared.
    @JvmStatic
    fun shareFile(path: String, mime: String, title: String) {
      val activity = instance
        ?: throw IllegalStateException("shareFile: no live MainActivity")
      val file = File(path)
      val uri = FileProvider.getUriForFile(
        activity,
        activity.packageName + ".fileprovider",
        file,
      )
      val send = Intent(Intent.ACTION_SEND).apply {
        type = mime
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      }
      val chooser = Intent.createChooser(send, title).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      }
      activity.startActivity(chooser)
    }
  }
}
KOTLIN

echo "==> patched $MAIN_ACTIVITY"
