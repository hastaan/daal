package org.daal.desktop.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ResolverGateTest {
  private val app = "app"
  private val svc = "service"
  private val wifi = 101L
  private val mobile = 202L
  private val a = listOf("192.0.2.1", "2001:db8::1")
  private val b = listOf("198.51.100.7")

  /** Sends what the gate answered and says the engine took it. */
  private fun ResolverGate.take(answer: List<String>?): List<String>? {
    if (answer != null) delivered(answer, true)
    return answer
  }

  @Test
  fun nothingIsSentBeforeAnyoneSpeaks() {
    val g = ResolverGate()
    assertNull(g.pending())
    assertNull(g.wanted())
  }

  @Test
  fun firstListIsSentAndTheSameListFromTheOtherReporterIsNot() {
    val g = ResolverGate()
    assertEquals(a, g.take(g.link(app, wifi, a)))
    assertNull(g.link(svc, wifi, a))
    assertNull(g.pending())
  }

  @Test
  fun changedServersOnTheSameNetworkAreSent() {
    val g = ResolverGate()
    g.take(g.link(app, wifi, a))
    assertEquals(b, g.take(g.link(svc, wifi, b)))
  }

  @Test
  fun lateLostOfTheOldNetworkDoesNotWipeTheNewList() {
    val g = ResolverGate()
    g.take(g.link(app, wifi, a))
    g.take(g.link(svc, wifi, a))
    // Wi-Fi -> mobile data: the service hears mobile first ...
    assertEquals(b, g.take(g.link(svc, mobile, b)))
    // ... then both hear Wi-Fi lost, the app last.
    assertNull(g.lost(svc, wifi))
    assertNull(g.lost(app, wifi))
    assertEquals(b, g.wanted())
    // The app then hears mobile too: same list, nothing sent.
    assertNull(g.link(app, mobile, b))
  }

  @Test
  fun lostOfAnUnknownNetworkChangesNothingWhileOneIsKnown() {
    val g = ResolverGate()
    g.take(g.link(svc, mobile, b))
    assertNull(g.lost(app, 999L))
  }

  @Test
  fun lostOfTheOnlyNetworkSendsEmpty() {
    val g = ResolverGate()
    g.take(g.link(app, wifi, a))
    assertEquals(emptyList<String>(), g.take(g.lost(app, wifi)))
    // The other reporter's lost for the same network: already empty.
    assertNull(g.lost(svc, wifi))
  }

  @Test
  fun lostOfTheCurrentFallsBackToAnotherKnownNetwork() {
    // Before Android 12 every matching network calls back.
    val g = ResolverGate()
    g.take(g.link(app, mobile, b))
    g.take(g.link(app, wifi, a))
    assertEquals(b, g.take(g.lost(app, wifi)))
  }

  @Test
  fun aSendTheEngineDidNotTakeIsSentAgain() {
    val g = ResolverGate()
    val first = g.link(app, wifi, a)
    assertEquals(a, first)
    g.delivered(a, false) // library not loaded yet
    assertEquals(a, g.pending())
    // The next event, even the same list, sends it again.
    assertEquals(a, g.link(svc, wifi, a))
    g.delivered(a, true)
    assertNull(g.pending())
  }

  @Test
  fun detachSendsNothingAndForgetsOnlyWhatThatReporterAloneKnew() {
    val g = ResolverGate()
    g.take(g.link(app, wifi, a))
    g.take(g.link(svc, wifi, a))
    g.detach(svc)
    assertNull(g.pending())
    assertEquals(a, g.wanted())
  }

  @Test
  fun lastReporterDetachingLeavesTheEngineAlone() {
    val g = ResolverGate()
    g.take(g.link(app, wifi, a))
    g.detach(app)
    assertNull(g.pending())
    assertNull(g.wanted())
    // Listening again: the same list is news to nobody.
    assertNull(g.link(app, wifi, a))
  }

  @Test
  fun aFailedSendBeforeDetachIsNotRetriedWithEmpty() {
    val g = ResolverGate()
    g.link(app, wifi, a)
    g.delivered(a, false)
    g.detach(app)
    assertNull(g.pending())
  }

  // Android 12+: a reporter follows one network at a time and gets no
  // "lost" for the network it left (registerBestMatchingNetworkCallback).
  @Test
  fun singleNetworkReporterLeavesNothingStaleBehind() {
    val g = ResolverGate()
    assertEquals(a, g.take(g.link(app, wifi, a, single = true)))
    assertEquals(b, g.take(g.link(app, mobile, b, single = true)))
    // No "lost" ever came for Wi-Fi. Mobile data is now lost, nothing left.
    assertEquals(emptyList<String>(), g.take(g.lost(app, mobile)))
  }

  @Test
  fun singleNetworkTwoReportersWithTheServiceDetachedInBetween() {
    val g = ResolverGate()
    g.take(g.link(app, wifi, a, single = true))
    g.take(g.link(svc, wifi, a, single = true))
    // The app hears mobile first; the service still sits on Wi-Fi.
    assertEquals(b, g.take(g.link(app, mobile, b, single = true)))
    // The service stops before it hears the move.
    g.detach(svc)
    assertEquals(emptyList<String>(), g.take(g.lost(app, mobile)))
  }

  @Test
  fun singleNetworkOtherReporterStillOnTheOldNetworkKeepsItKnown() {
    val g = ResolverGate()
    g.take(g.link(app, wifi, a, single = true))
    g.take(g.link(svc, wifi, a, single = true))
    assertEquals(b, g.take(g.link(app, mobile, b, single = true)))
    // The service moves too: Wi-Fi is now on nobody's list.
    assertNull(g.link(svc, mobile, b, single = true))
    assertEquals(emptyList<String>(), g.take(g.lost(svc, mobile)))
  }
}
