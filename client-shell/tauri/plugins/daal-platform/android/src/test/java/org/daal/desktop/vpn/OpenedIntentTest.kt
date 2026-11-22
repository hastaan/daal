package org.daal.desktop.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenedIntentTest {
  private val pkg = "org.daal.desktop"
  private val telegram = "content://org.telegram.messenger.provider/media/Telegram/Telegram%20Files/maman.sbpx"

  @Test
  fun aFileOpenedFromAMessengerIsTaken() {
    val o = decideOpened(IntentFacts(INTENT_ACTION_VIEW, telegram, null, null), pkg)
    assertEquals(Opened.File(telegram), o)
  }

  @Test
  fun aFileSharedToDaalIsTakenAndItsCaptionIgnored() {
    val wa = "content://com.whatsapp.provider.media/item/12345"
    val o = decideOpened(IntentFacts(INTENT_ACTION_SEND, null, wa, "here is your file"), pkg)
    assertEquals(Opened.File(wa), o)
  }

  @Test
  fun sharedTextIsTaken() {
    val text = "salam, ino bezan: RFNCUAABxxxx"
    assertEquals(Opened.Text(text), decideOpened(IntentFacts(INTENT_ACTION_SEND, null, null, text), pkg))
  }

  @Test
  fun blankOrHugeTextIsNotTaken() {
    assertNull(decideOpened(IntentFacts(INTENT_ACTION_SEND, null, null, "  \n "), pkg))
    assertNull(decideOpened(IntentFacts(INTENT_ACTION_SEND, null, null, null), pkg))
    val huge = "A".repeat(MAX_OPENED_BYTES + 1)
    assertNull(decideOpened(IntentFacts(INTENT_ACTION_SEND, null, null, huge), pkg))
  }

  @Test
  fun otherActionsAreNotTaken() {
    assertNull(decideOpened(IntentFacts("android.intent.action.MAIN", null, null, null), pkg))
    assertNull(decideOpened(IntentFacts("android.intent.action.SEND_MULTIPLE", null, telegram, null), pkg))
    assertNull(decideOpened(IntentFacts(null, telegram, null, null), pkg))
    assertNull(decideOpened(IntentFacts(INTENT_ACTION_VIEW, null, null, null), pkg))
  }

  @Test
  fun reopeningFromRecentAppsDoesNotOfferTheFileAgain() {
    val f = IntentFacts(INTENT_ACTION_VIEW, telegram, null, null, flags = FLAG_LAUNCHED_FROM_HISTORY or 0x10000000)
    assertNull(decideOpened(f, pkg))
  }

  @Test
  fun aSharedStreamThatIsRefusedDoesNotFallBackToTheText() {
    val f = IntentFacts(INTENT_ACTION_SEND, null, "file:///sdcard/x.sbpx", "RFNCUAAB")
    assertNull(decideOpened(f, pkg))
  }

  @Test
  fun onlyAnotherAppsContentUrisAreAccepted() {
    assertTrue(acceptableUri(telegram, pkg))
    assertTrue(acceptableUri("CONTENT://com.android.providers.downloads.documents/document/12", pkg))
    // file:// would be read with Daal's own rights.
    assertFalse(acceptableUri("file:///data/data/org.daal.desktop/files/daal_dwk_v1.bin", pkg))
    assertFalse(acceptableUri("file:///sdcard/Download/x.sbpx", pkg))
    // Daal's own provider exposes its cache.
    assertFalse(acceptableUri("content://org.daal.desktop.fileprovider/my_cache_images/x", pkg))
    assertFalse(acceptableUri("content://org.daal.desktop/x", pkg))
    assertFalse(acceptableUri("content://ORG.DAAL.DESKTOP.fileprovider/x", pkg))
    // Not URIs Daal opens.
    assertFalse(acceptableUri("https://example.com/x.sbpx", pkg))
    assertFalse(acceptableUri("javascript:alert(1)", pkg))
    assertFalse(acceptableUri("content://", pkg))
    assertFalse(acceptableUri("content:///x", pkg))
    assertFalse(acceptableUri("content://user@org.daal.desktop.fileprovider/x", pkg))
    // A look-alike of another package is not ours.
    assertTrue(acceptableUri("content://org.daal.desktopx.provider/x", pkg))
  }

  @Test
  fun theStagedNameIsAlwaysOnePlainFileName() {
    val f = Opened.File(telegram)
    assertEquals("opened-ab12.sbpx", stagedOpenedName(f, "maman.sbpx", "ab12"))
    assertEquals("opened-ab12.sbpx", stagedOpenedName(f, "maman (1).SBPX ", "ab12"))
    assertEquals("opened-ab12.sbp", stagedOpenedName(f, "relaypack.sbp", "ab12"))
    assertEquals("opened-ab12.bin", stagedOpenedName(f, "12345", "ab12"))
    assertEquals("opened-ab12.bin", stagedOpenedName(f, null, "ab12"))
    assertEquals("opened-ab12.txt", stagedOpenedName(Opened.Text("x"), "x.sbpx", "ab12"))
    // The sender's name never becomes a path, and a bad tag is replaced.
    assertEquals("opened-0.bin", stagedOpenedName(f, "../../files/x", "../x"))
    assertEquals("opened-0.sbp", stagedOpenedName(f, "../x.sbp", ""))
  }

  @Test
  fun theLastSegmentIsTheNameToFallBackOn() {
    assertEquals("maman.sbpx", lastSegment(telegram))
    assertEquals("x.sbp", lastSegment("content://a.b/c/x.sbp?y=1"))
    assertEquals("c", lastSegment("content://a.b/c/"))
    assertNull(lastSegment(""))
  }
}
