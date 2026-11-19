package org.daal.desktop.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class SavedNameTest {
  @Test
  fun theStoredNameWinsWhenThereIsOne() {
    val asked = "daal-backup-2026-11-19-1030.daalbackup"
    assertEquals(
      "daal-backup-2026-11-19-1030 (1).daalbackup",
      savedName(asked, "daal-backup-2026-11-19-1030 (1).daalbackup"),
    )
    assertEquals(asked, savedName(asked, asked))
  }

  @Test
  fun noStoredNameMeansTheOneAskedFor() {
    val asked = "x.sbp"
    assertEquals(asked, savedName(asked, null))
    assertEquals(asked, savedName(asked, ""))
    assertEquals(asked, savedName(asked, "   "))
    assertEquals(asked, savedName(asked, "a/b.sbp"))
  }
}
