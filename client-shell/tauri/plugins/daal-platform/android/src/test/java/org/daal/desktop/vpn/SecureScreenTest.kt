package org.daal.desktop.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureScreenTest {
  @Test
  fun onSetsTheFlagOnceAndOffClearsIt() {
    val s = SecureScreen()
    assertFalse("a new window is capturable", s.applied)
    assertEquals(SecureFlagChange.ADD, s.request(true))
    assertTrue(s.applied)
    assertEquals(SecureFlagChange.NONE, s.request(true))
    assertEquals(SecureFlagChange.CLEAR, s.request(false))
    assertFalse(s.applied)
    assertEquals(SecureFlagChange.NONE, s.request(false))
  }

  @Test
  fun aLoadedPageStartsClearWhateverWasAskedBefore() {
    val s = SecureScreen()
    s.request(true)
    assertEquals(SecureFlagChange.CLEAR, s.atLoad())
    assertFalse(s.applied)
    // ...and asking again after the load sets it again.
    assertEquals(SecureFlagChange.ADD, s.request(true))
  }
}
