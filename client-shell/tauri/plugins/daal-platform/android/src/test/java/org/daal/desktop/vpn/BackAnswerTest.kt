package org.daal.desktop.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackAnswerTest {
  @Test
  fun onlyALiteralTrueKeepsTheAppOpen() {
    assertTrue(backWasHandled("true"))
    assertTrue(backWasHandled(" true\n"))
    assertFalse(backWasHandled("false"))
    assertFalse(backWasHandled("null"))
    assertFalse(backWasHandled(null))
    assertFalse(backWasHandled("\"true\""))
    assertFalse(backWasHandled(""))
  }

  @Test
  fun theQuestionNeverThrowsIntoThePage() {
    assertTrue(BACK_JS.contains("__daalBack"))
    assertTrue(BACK_JS.contains("catch"))
  }
}
