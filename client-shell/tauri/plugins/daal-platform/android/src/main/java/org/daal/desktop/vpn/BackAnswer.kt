package org.daal.desktop.vpn

// The system Back question the shell puts to the page, kept free of
// Android types so it runs in the plain-JVM tests
// (tools/test-android-jvm.sh). Used by platform/DaalPlatformPlugin.load.

/** What the page is asked on Back; see DaalPlatformPlugin.load. */
const val BACK_JS =
  "(function(){try{return typeof window.__daalBack==='function'&&window.__daalBack()===true}catch(e){return false}})()"

/** `evaluateJavascript` hands back JSON text: only a literal true counts. */
fun backWasHandled(result: String?): Boolean = result?.trim() == "true"
