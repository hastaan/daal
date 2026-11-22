package org.daal.desktop.vpn

// "Open with Daal" and "Share to Daal": which incoming intents Daal
// takes, and the name a taken file is staged under. Kept free of
// Android types for the plain-JVM tests (tools/test-android-jvm.sh);
// platform/OpenedFiles reads the Intent and applies these rules.
//
// Nothing here imports anything. A file or text that is taken is only
// HANDED to the page, which shows it and lets the person decide
// (trust prompt, signature check): taking it is not a trust decision.

const val INTENT_ACTION_VIEW = "android.intent.action.VIEW"
const val INTENT_ACTION_SEND = "android.intent.action.SEND"

/** Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY. */
const val FLAG_LAUNCHED_FROM_HISTORY = 0x00100000

/**
 * The largest file or text Daal stages: 4 MiB, the same ceiling as a
 * pasted text (daal-wizard recipient_paste MAX_INPUT_BYTES). A real
 * file is a few KB; anything bigger is not one.
 */
const val MAX_OPENED_BYTES = 4 * 1024 * 1024

/** What an incoming intent hands Daal. */
sealed class Opened {
  /** A content:// URI another app granted read access to. */
  data class File(val uri: String) : Opened()

  /** Text shared to Daal (a Daal file pasted as text, or anything else). */
  data class Text(val text: String) : Opened()
}

/** The plain facts read off an Intent; see platform/OpenedFiles. */
data class IntentFacts(
  val action: String?,
  /** Intent.getDataString(). */
  val data: String?,
  /** EXTRA_STREAM as a string, when it is a single Uri. */
  val stream: String?,
  /** EXTRA_TEXT. */
  val text: String?,
  val flags: Int = 0,
)

/**
 * The file or text an intent hands Daal, or null when Daal does not
 * take it.
 *
 * - VIEW: the intent's data URI.
 * - SEND: the single EXTRA_STREAM if there is one (a caption that
 *   comes with it is ignored), otherwise EXTRA_TEXT.
 * - An intent re-delivered because the person opened Daal from the
 *   recent-apps list is not taken again: it was handled when it came.
 */
fun decideOpened(f: IntentFacts, ownPackage: String): Opened? {
  if (f.flags and FLAG_LAUNCHED_FROM_HISTORY != 0) return null
  return when (f.action) {
    INTENT_ACTION_VIEW -> {
      val uri = f.data ?: return null
      if (acceptableUri(uri, ownPackage)) Opened.File(uri) else null
    }
    INTENT_ACTION_SEND -> {
      val stream = f.stream
      if (!stream.isNullOrBlank()) {
        return if (acceptableUri(stream, ownPackage)) Opened.File(stream) else null
      }
      val text = f.text ?: return null
      if (text.isBlank() || text.length > MAX_OPENED_BYTES) null else Opened.Text(text)
    }
    else -> null
  }
}

/**
 * Only content:// URIs from ANOTHER app's provider.
 *
 * - file:// is refused: since Android 7 no app may send one, and one
 *   that did would make Daal read a path with Daal's own rights
 *   (its private keys included).
 * - Daal's own provider (`<package>.fileprovider`, which exposes the
 *   cache) is refused for the same reason: another app could not read
 *   it, but could ask Daal to.
 */
fun acceptableUri(uri: String, ownPackage: String): Boolean {
  val prefix = "content://"
  if (uri.length <= prefix.length || !uri.regionMatches(0, prefix, 0, prefix.length, ignoreCase = true)) {
    return false
  }
  val rest = uri.substring(prefix.length)
  val authority = rest.substringBefore('/').substringBefore('?').substringBefore('#')
  if (authority.isEmpty() || authority.contains('@') || authority.any { it.isWhitespace() || it == '\u0000' }) {
    return false
  }
  val a = authority.lowercase()
  val own = ownPackage.lowercase()
  if (own.isNotEmpty() && (a == own || a.startsWith("$own."))) return false
  return true
}

/**
 * The extension a staged file gets, from the name the sending app
 * gave it. Only a hint: the page checks the bytes, not the name.
 * Messengers rename a second copy "x (1).sbpx", which still ends in
 * the extension.
 */
fun openedExtension(name: String?): String {
  val n = name?.trim()?.lowercase().orEmpty()
  return when {
    n.endsWith(".sbpx") -> "sbpx"
    n.endsWith(".sbp") -> "sbp"
    else -> "bin"
  }
}

/**
 * The name a taken file or text is staged under: `opened-<tag>.<ext>`.
 * The sending app's name is never used as a path (it could hold "../"),
 * and a tag that is not plain hex is replaced, so the result is always
 * one plain file name.
 */
fun stagedOpenedName(opened: Opened, sourceName: String?, tag: String): String {
  val safeTag = if (tag.isNotEmpty() && tag.length <= 64 && tag.all { it in '0'..'9' || it in 'a'..'f' }) tag else "0"
  val ext = when (opened) {
    is Opened.Text -> "txt"
    is Opened.File -> openedExtension(sourceName)
  }
  return "opened-$safeTag.$ext"
}

/** The last path segment of a URI, the name to fall back on when the provider gives none. */
fun lastSegment(uri: String): String? {
  val path = uri.substringBefore('?').substringBefore('#')
  val seg = path.trimEnd('/').substringAfterLast('/')
  return seg.ifEmpty { null }
}
