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
# Idempotent: rewrites the files to the canonical content every run.

set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
APP_DIR="${APP_DIR:-$ROOT/client-shell/tauri/src-tauri/gen/android/app}"
PKG_DIR="$APP_DIR/src/main/java/org/daal/desktop"
MAIN_ACTIVITY="${MAIN_ACTIVITY:-$PKG_DIR/MainActivity.kt}"
DAAL_KEYSTORE="${DAAL_KEYSTORE:-$PKG_DIR/DaalKeystore.kt}"
PROGUARD_KEEP="${PROGUARD_KEEP:-$APP_DIR/proguard-daal.pro}"

if [ ! -d "$(dirname "$MAIN_ACTIVITY")" ]; then
  echo "FATAL: $(dirname "$MAIN_ACTIVITY") not found (run \`tauri android init\` first)" >&2
  exit 1
fi

cat > "$MAIN_ACTIVITY" <<'KOTLIN'
package org.daal.desktop

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.annotation.Keep
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
    //
    // @Keep + the proguard-daal.pro rule this script also writes are
    // BOTH required: the release build minifies (R8), and shareFile is
    // reached only by JNI reflection, so without an explicit keep R8
    // strips/renames it and the Rust call throws NoSuchMethodError.
    @JvmStatic
    var instance: MainActivity? = null

    // shareFile(path, mime, title): grant a content:// URI over the
    // app FileProvider and launch an ACTION_SEND chooser. Called from
    // Rust via JNI (signature (String,String,String)V). Throws (as a
    // Java exception surfaced to the Rust caller) if no Activity is
    // live or the file cannot be shared.
    @Keep
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

# DaalKeystore.kt — AndroidKeyStore-backed device wrapping key (DWK).
# The Rust device-custody layer (src-tauri/src/custody.rs) JNI-calls the
# static getOrCreateDwk()/isHardwareBacked(); this class was hand-added
# to the gitignored gen/ tree in a past session and lost on re-init,
# so a clean build threw ClassNotFoundException: DaalKeystore when the
# recipient identity was created. A random 32-byte DWK is generated
# once, sealed with an AndroidKeyStore AES-256-GCM key, persisted, and
# returned on subsequent calls.
cat > "$DAAL_KEYSTORE" <<'KOTLIN'
package org.daal.desktop

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.Keep
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

// Device wrapping key (DWK) custody, called from Rust via JNI
// (src-tauri/src/custody.rs). A 32-byte DWK is generated once and
// sealed at rest with a non-exportable AndroidKeyStore AES-256-GCM
// key; getOrCreateDwk() returns the plaintext DWK to the caller.
@Keep
object DaalKeystore {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val WRAPPER_ALIAS = "daal_dwk_wrapper_v1"
    private const val DWK_LEN = 32
    private const val IV_LEN = 12
    private const val TAG_BITS = 128
    private const val WRAP_FILENAME = "daal_dwk_v1.bin"

    private fun appContext(): Context =
        MainActivity.instance?.applicationContext
            ?: throw IllegalStateException("DaalKeystore: no application context (activity not started)")

    private fun wrapperKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(WRAPPER_ALIAS, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(
            KeyGenParameterSpec.Builder(
                WRAPPER_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return kg.generateKey()
    }

    @Keep
    @JvmStatic
    fun getOrCreateDwk(): ByteArray {
        val f = File(appContext().filesDir, WRAP_FILENAME)
        val key = wrapperKey()
        if (f.exists()) {
            val blob = f.readBytes()
            val iv = blob.copyOfRange(0, IV_LEN)
            val ct = blob.copyOfRange(IV_LEN, blob.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            return cipher.doFinal(ct)
        }
        val dwk = ByteArray(DWK_LEN).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ct = cipher.doFinal(dwk)
        val tmp = File.createTempFile("dwk", ".tmp", appContext().filesDir)
        tmp.writeBytes(iv + ct)
        if (!tmp.renameTo(f)) {
            tmp.copyTo(f, overwrite = true)
            tmp.delete()
        }
        return dwk
    }

    @Keep
    @JvmStatic
    fun isHardwareBacked(): Boolean {
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val key = ks.getKey(WRAPPER_ALIAS, null) as? SecretKey ?: return false
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                @Suppress("DEPRECATION")
                info.isInsideSecureHardware
            }
        } catch (_: Throwable) {
            false
        }
    }
}
KOTLIN

# R8 keep rules — the app build.gradle.kts pulls in every **/*.pro
# under app/ via fileTree("."), so this file is picked up
# automatically. Keeps the JNI-reached members of MainActivity
# (shareFile + instance) and the whole DaalKeystore object, all of
# which are reached only by reflection and would otherwise be stripped
# or renamed by the release R8 pass.
cat > "$PROGUARD_KEEP" <<'PROGUARD'
# Daal: keep JNI-invoked Android members. Written by
# tools/patch-android-mainactivity.sh. Without these the release R8
# pass strips the reflection-only entrypoints and the Rust shell fails
# with NoSuchMethodError / ClassNotFoundException.
-keep class org.daal.desktop.MainActivity {
    public static void shareFile(java.lang.String, java.lang.String, java.lang.String);
    public static *** instance;
    public static *** getInstance();
    public static void setInstance(***);
}
-keep class org.daal.desktop.DaalKeystore { *; }
PROGUARD

echo "==> patched $MAIN_ACTIVITY"
echo "==> wrote $DAAL_KEYSTORE"
echo "==> wrote $PROGUARD_KEEP"
