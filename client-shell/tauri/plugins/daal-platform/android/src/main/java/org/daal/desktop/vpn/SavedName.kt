package org.daal.desktop.vpn

// The name a file saved to Downloads was actually stored under (PB-3),
// kept free of Android types for the plain-JVM tests. MediaStore may
// store a different name than the one asked for ("x (1).daalbackup"
// when "x.daalbackup" exists): the screen must name the file that is
// there. Used by platform/DownloadsSaver.

/** The stored name if MediaStore reported one, else the one asked for. */
fun savedName(requested: String, stored: String?): String {
  val s = stored?.trim().orEmpty()
  return if (s.isEmpty() || s.contains('/') || s.contains('\u0000')) requested else s
}
