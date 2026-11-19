package org.daal.desktop.vpn

import org.daal.desktop.vpn.NetworkWatch.Caps
import org.daal.desktop.vpn.NetworkWatch.Facts
import org.daal.desktop.vpn.NetworkWatch.Link
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for what DaalVpnService tells the engine about the phone's
 * network, and when. No Android: the events are the ones a
 * ConnectivityManager.NetworkCallback delivers, in the orders a phone
 * delivers them. Run by tools/test-android-jvm.sh.
 */
class NetworkWatchTest {

  private val homeWifi = Caps(wifi = true, validated = true, notMetered = true)
  private val homeLink = Link(v4Subnets = listOf("192.168.1.0/24"), v4Gateway = "192.168.1.1")
  private val cafeLink = Link(v4Subnets = listOf("10.4.0.0/16"), v4Gateway = "10.4.0.1")
  private val mobile = Caps(cellular = true, validated = true, notMetered = false, operator = "43211")
  private val mobileLink = Link(v4Subnets = listOf("10.117.3.0/29"), v4Gateway = "10.117.3.1")

  private fun homeFacts() = Facts("wifi", NetworkWatch.networkId("wifi", "", homeLink), 1, 0)
  private fun mobileFacts() = Facts("cellular", NetworkWatch.networkId("cellular", "43211", Link()), 1, 1)

  /** A watch already past its first report: on home wifi, delivered. */
  private fun onHomeWifi(): NetworkWatch {
    val w = NetworkWatch()
    w.start(hasNetwork = true, nowMs = 0)
    w.available(1, 0)
    w.capabilities(1, homeWifi, 0)
    w.link(1, homeLink, 0)
    val f = w.due(0)
    assertEquals(homeFacts(), f)
    w.delivered(f!!, ok = true, nowMs = 0)
    return w
  }

  // ---- the first report ----

  @Test
  fun theFirstFactsGoAtOnceAndOnlyWhenTheNetworkIsDescribed() {
    val w = NetworkWatch()
    // Android names a network; nothing is known about it yet.
    assertEquals(NetworkWatch.DESCRIBE_WAIT_MS, w.start(hasNetwork = true, nowMs = 0))
    assertNull(w.due(0))
    w.available(7, 10)
    assertNull(w.due(10))
    // Capabilities alone are half a description.
    w.capabilities(7, homeWifi, 20)
    assertNull(w.due(20))
    // With the addresses it is whole: due now, no settling time.
    assertEquals(0L, w.link(7, homeLink, 30))
    assertEquals(homeFacts(), w.due(30))
    // And only once.
    assertNull(w.due(31))
    assertNull(w.nextIn(31))
  }

  @Test
  fun startingWithNoNetworkSaysSoAtOnce() {
    // Airplane mode: Android calls nothing back, so the start itself
    // is the observation.
    val w = NetworkWatch()
    assertEquals(0L, w.start(hasNetwork = false, nowMs = 0))
    assertEquals(NetworkWatch.NONE, w.due(0))
    assertEquals("none", NetworkWatch.NONE.kind)
    assertEquals(0, NetworkWatch.NONE.validated)
    assertEquals(-1, NetworkWatch.NONE.metered)
  }

  @Test
  fun aNetworkAndroidNeverDescribesIsReportedAsUnknown() {
    val w = NetworkWatch()
    w.start(hasNetwork = true, nowMs = 0)
    assertNull(w.due(NetworkWatch.DESCRIBE_WAIT_MS - 1))
    assertEquals(Facts("other", "", -1, -1), w.due(NetworkWatch.DESCRIBE_WAIT_MS))
  }

  @Test
  fun capabilitiesWithoutAddressesAreSentOnceTheWaitIsOver() {
    // API 24/25 do not promise a link-properties callback.
    val w = NetworkWatch()
    w.start(hasNetwork = true, nowMs = 0)
    w.available(3, 0)
    w.capabilities(3, mobile, 0)
    assertNull(w.due(100))
    assertEquals(mobileFacts(), w.due(NetworkWatch.DESCRIBE_WAIT_MS))
  }

  // ---- identical facts are sent once ----

  @Test
  fun repeatedIdenticalEventsSendNothing() {
    val w = onHomeWifi()
    // Android repeats capabilities on every change of signal strength.
    for (t in 1L..50L) {
      assertNull(w.capabilities(1, homeWifi, t * 100))
      assertNull(w.link(1, homeLink, t * 100))
      assertNull(w.due(t * 100))
    }
  }

  // ---- changes wait to settle ----

  @Test
  fun aChangeOnTheSameNetworkWaitsToSettle() {
    val w = onHomeWifi()
    // The system loses its way to the internet through this wifi.
    assertEquals(NetworkWatch.SETTLE_MS, w.capabilities(1, homeWifi.copy(validated = false), 1_000))
    assertNull(w.due(1_000 + NetworkWatch.SETTLE_MS - 1))
    assertEquals(homeFacts().copy(validated = 0), w.due(1_000 + NetworkWatch.SETTLE_MS))
  }

  @Test
  fun aFlickerThatComesBackIsNotAChange() {
    val w = onHomeWifi()
    w.capabilities(1, homeWifi.copy(validated = false), 1_000)
    // Back before it settled: the engine already has exactly this.
    assertNull(w.capabilities(1, homeWifi, 1_300))
    assertNull(w.due(5_000))
  }

  @Test
  fun aLostNetworkIsReportedAsNoneAfterALongerWait() {
    val w = onHomeWifi()
    assertEquals(NetworkWatch.NONE_SETTLE_MS, w.lost(1, 1_000))
    assertNull(w.due(1_000 + NetworkWatch.SETTLE_MS))
    assertNull(w.due(1_000 + NetworkWatch.NONE_SETTLE_MS - 1))
    assertEquals(NetworkWatch.NONE, w.due(1_000 + NetworkWatch.NONE_SETTLE_MS))
  }

  @Test
  fun wifiToMobileThroughAMomentOfNothingReportsOnlyMobile() {
    val w = onHomeWifi()
    w.lost(1, 1_000)
    // 400 ms later mobile data is the default network.
    w.available(2, 1_400)
    w.capabilities(2, mobile, 1_450)
    // The moment "none" would have gone: a network exists again, so it
    // is no longer true and is not sent.
    assertNull(w.due(1_000 + NetworkWatch.NONE_SETTLE_MS))
    val wait = w.link(2, mobileLink, 3_050)
    assertEquals(NetworkWatch.SETTLE_MS, wait)
    assertNull(w.due(3_050 + NetworkWatch.SETTLE_MS - 1))
    assertEquals(mobileFacts(), w.due(3_050 + NetworkWatch.SETTLE_MS))
    assertNull(w.due(60_000))
  }

  @Test
  fun theOldNetworkLostAfterTheNewOneWasNamedIsNotALoss() {
    val w = onHomeWifi()
    w.available(2, 1_000)
    w.capabilities(2, mobile, 1_000)
    w.link(2, mobileLink, 1_000)
    // Android reports the wifi gone only now.
    w.lost(1, 1_100)
    assertEquals(mobileFacts(), w.due(1_000 + NetworkWatch.SETTLE_MS))
    assertNull(w.due(60_000))
  }

  @Test
  fun aBlipBackOntoTheSameNetworkSendsNothing() {
    val w = onHomeWifi()
    w.lost(1, 1_000)
    // The same wifi again under a new handle (Android numbers every
    // connection anew): the id is what says it is the same network.
    w.available(9, 1_500)
    w.capabilities(9, homeWifi, 1_520)
    assertNull(w.link(9, homeLink, 1_540))
    assertNull(w.due(60_000))
  }

  @Test
  fun aNetworkThatNeverStopsChangingIsStillReported() {
    val w = onHomeWifi()
    var t = 1_000L
    var metered = true
    var sent: Facts? = null
    // Flips every 500 ms, always inside the settling time.
    while (t <= 1_000 + NetworkWatch.MAX_WAIT_MS && sent == null) {
      // Alternates between two states that both differ from what was sent.
      w.capabilities(1, homeWifi.copy(validated = false, notMetered = !metered), t)
      metered = !metered
      sent = w.due(t)
      t += 500
    }
    assertTrue("reported no later than MAX_WAIT_MS after the first change", sent != null)
    assertEquals(0, sent!!.validated)
  }

  // ---- our own VPN is not the network ----

  @Test
  fun eventsAboutAVpnNetworkAreDropped() {
    val w = onHomeWifi()
    assertNull(w.capabilities(55, Caps(vpn = true, validated = true, notMetered = true), 1_000))
    assertNull(w.due(60_000))
    // And the network under it is still the one described.
    assertEquals(NetworkWatch.SETTLE_MS, w.capabilities(1, homeWifi.copy(notMetered = false), 61_000))
  }

  /** The order a phone delivers them in: named, then described. */
  @Test
  fun aVpnNetworkNamedBeforeItIsDescribedDoesNotReplaceTheRealOne() {
    val w = onHomeWifi()
    // Android: "55 is the default network now" … "55 is a VPN" … "55's
    // addresses" — and nothing of it is the network under the tunnel.
    w.available(55, 1_000)
    w.capabilities(55, Caps(vpn = true, validated = true, notMetered = true), 1_001)
    w.link(55, Link(v4Subnets = listOf("10.7.0.0/30"), v4Gateway = ""), 1_002)
    assertNull("nothing may be waiting to be sent", w.nextIn(1_003))
    var now = 1_003L
    while (now < 60_000) {
      assertNull("the engine was told something about a VPN network at $now", w.due(now))
      now += 250
    }
    // The real network is still the one described: a change on it is a
    // change, an identical event is not.
    assertNull(w.capabilities(1, homeWifi, 61_000))
    assertEquals(NetworkWatch.SETTLE_MS, w.capabilities(1, homeWifi.copy(notMetered = false), 61_000))
    // The VPN going away is not the network going away.
    val w2 = onHomeWifi()
    w2.available(55, 1_000)
    w2.capabilities(55, Caps(vpn = true), 1_000)
    assertNull(w2.lost(55, 2_000))
    assertNull(w2.due(60_000))
    // …and the real one going away while the VPN is "the default" is.
    val w3 = onHomeWifi()
    w3.available(55, 1_000)
    w3.capabilities(55, Caps(vpn = true), 1_000)
    w3.lost(1, 2_000)
    assertEquals(NetworkWatch.NONE, w3.due(2_000 + NetworkWatch.NONE_SETTLE_MS))
  }

  // ---- the first facts, before the connect ----

  @Test
  fun aNetworkDescribedAtStartIsReportedBeforeAnythingElseHappens() {
    val w = NetworkWatch()
    // Whole and at once: the service delivers these before it starts
    // the connect.
    assertEquals(homeFacts(), w.startDescribed(1, homeWifi, homeLink, 0))
    assertNull("handed out twice", w.due(0))
    w.delivered(homeFacts(), ok = true, nowMs = 0)
    // The callbacks then repeat what was already said: nothing to send.
    assertNull(w.available(1, 5))
    assertNull(w.capabilities(1, homeWifi, 6))
    assertNull(w.link(1, homeLink, 7))
    assertNull(w.due(60_000))
  }

  @Test
  fun anUndescribedOrVpnNetworkAtStartWaitsForTheCallbacks() {
    for ((caps, link) in listOf<Pair<Caps?, Link?>>(null to homeLink, homeWifi to null, Caps(vpn = true) to homeLink)) {
      val w = NetworkWatch()
      assertNull(w.startDescribed(1, caps, link, 0))
      assertNull("nothing is known yet", w.due(0))
      // Exactly as start(hasNetwork = true): the callbacks describe it.
      w.available(2, 10)
      w.capabilities(2, homeWifi, 10)
      w.link(2, homeLink, 10)
      assertEquals(homeFacts(), w.due(10))
    }
  }

  // ---- a failed engine call ----

  @Test
  fun aFailedCallIsRepeatedAFewTimesThenLeftUntilTheNetworkChanges() {
    val w = NetworkWatch()
    w.start(hasNetwork = true, nowMs = 0)
    w.available(1, 0)
    w.capabilities(1, homeWifi, 0)
    w.link(1, homeLink, 0)
    var now = 0L
    var calls = 0
    while (true) {
      val f = w.due(now) ?: break
      calls++
      val again = w.delivered(f, ok = false, nowMs = now)
      if (again == null) break
      assertEquals(NetworkWatch.RETRY_MS, again)
      now += again
    }
    assertEquals(1 + NetworkWatch.MAX_RETRIES, calls)
    assertNull(w.due(now + 600_000))
    // A change is tried regardless.
    w.capabilities(1, homeWifi.copy(notMetered = false), now + 600_000)
    assertEquals(homeFacts().copy(metered = 1), w.due(now + 600_000))
  }

  @Test
  fun aRepeatThatSucceedsEndsTheRepeats() {
    val w = NetworkWatch()
    w.start(hasNetwork = false, nowMs = 0)
    val f = w.due(0)!!
    assertEquals(NetworkWatch.RETRY_MS, w.delivered(f, ok = false, nowMs = 0))
    val again = w.due(NetworkWatch.RETRY_MS)
    assertEquals(f, again)
    assertNull(w.delivered(again!!, ok = true, nowMs = NetworkWatch.RETRY_MS))
    assertNull(w.due(600_000))
  }

  // ---- stop ----

  @Test
  fun afterStopNothingIsSentAndAStartReportsAfresh() {
    val w = onHomeWifi()
    w.stop()
    assertNull(w.lost(1, 1_000))
    assertNull(w.due(60_000))
    // The next connection reports again, even the same network.
    w.start(hasNetwork = true, nowMs = 70_000)
    w.available(1, 70_000)
    w.capabilities(1, homeWifi, 70_000)
    w.link(1, homeLink, 70_000)
    assertEquals(homeFacts(), w.due(70_000))
  }

  // ---- kind, validated, metered ----

  @Test
  fun kindsAndFlags() {
    assertEquals("wifi", NetworkWatch.kind(Caps(wifi = true)))
    assertEquals("cellular", NetworkWatch.kind(Caps(cellular = true)))
    assertEquals("ethernet", NetworkWatch.kind(Caps(ethernet = true)))
    assertEquals("other", NetworkWatch.kind(Caps()))
    val w = NetworkWatch()
    w.start(hasNetwork = true, nowMs = 0)
    w.capabilities(1, Caps(cellular = true, validated = false, notMetered = false, operator = "43235"), 0)
    w.link(1, mobileLink, 0)
    val f = w.due(0)!!
    assertEquals("cellular", f.kind)
    assertEquals(0, f.validated)
    assertEquals(1, f.metered)
  }

  // ---- the id ----

  @Test
  fun theIdIsTheSameOnEveryReconnectToTheSameNetwork() {
    val a = NetworkWatch.networkId("wifi", "", homeLink)
    // A new lease: another host address in the same network gives the
    // same subnet; and the order Android lists things in does not matter.
    val again = Link(v4Subnets = listOf(NetworkWatch.subnet(byteArrayOf(192.toByte(), 168.toByte(), 1, 99), 24)), v4Gateway = "/192.168.1.1")
    assertEquals(a, NetworkWatch.networkId("wifi", "", again))
    assertEquals(
      NetworkWatch.networkId("wifi", "", Link(listOf("10.0.0.0/8", "192.168.1.0/24"), "192.168.1.1")),
      NetworkWatch.networkId("wifi", "", Link(listOf("192.168.1.0/24", "10.0.0.0/8"), "192.168.1.1")),
    )
    // IPv6 arriving a moment later does not change it.
    assertEquals(a, NetworkWatch.networkId("wifi", "", homeLink.copy(v6Gateway = "fe80::1%wlan0")))
  }

  @Test
  fun differentNetworksGetDifferentIds() {
    val home = NetworkWatch.networkId("wifi", "", homeLink)
    assertNotEquals(home, NetworkWatch.networkId("wifi", "", cafeLink))
    assertNotEquals(home, NetworkWatch.networkId("wifi", "", homeLink.copy(v4Gateway = "192.168.1.254")))
    assertNotEquals(home, NetworkWatch.networkId("ethernet", "", homeLink))
    assertNotEquals(
      NetworkWatch.networkId("cellular", "43211", Link()),
      NetworkWatch.networkId("cellular", "43235", Link()),
    )
  }

  @Test
  fun aMobileNetworkIsItsOperatorNotItsAddress() {
    val a = NetworkWatch.networkId("cellular", "43211", mobileLink)
    val b = NetworkWatch.networkId("cellular", "43211", Link(listOf("100.72.9.0/30"), "100.72.9.1"))
    assertEquals(a, b)
    assertTrue(a.isNotEmpty())
    // No operator readable: the kind alone is the identity.
    assertEquals("", NetworkWatch.networkId("cellular", "", mobileLink))
  }

  @Test
  fun anIpv6OnlyNetworkUsesItsGatewayWithoutTheZone() {
    val a = NetworkWatch.networkId("wifi", "", Link(v6Gateway = "fe80::aa:bbff:fecc:dd01%wlan0"))
    assertTrue(a.isNotEmpty())
    assertEquals(a, NetworkWatch.networkId("wifi", "", Link(v6Gateway = "FE80::AA:BBFF:FECC:DD01")))
    assertEquals("", NetworkWatch.networkId("wifi", "", Link()))
    assertEquals("", NetworkWatch.networkId("none", "", homeLink))
  }

  @Test
  fun theIdCarriesNoAddressAndNoOperatorCode() {
    val ids = listOf(
      NetworkWatch.networkId("wifi", "", homeLink),
      NetworkWatch.networkId("cellular", "43211", Link()),
      NetworkWatch.networkId("wifi", "", Link(v6Gateway = "fe80::1")),
    )
    for (id in ids) {
      assertEquals(32, id.length)
      assertTrue(id, id.all { it in '0'..'9' || it in 'a'..'f' })
      assertFalse(id.contains("192"))
      assertFalse(id.contains("43211"))
    }
  }

  @Test
  fun subnetIsTheNetworkAddressNotTheHostAddress() {
    assertEquals("192.168.1.0/24", NetworkWatch.subnet(byteArrayOf(192.toByte(), 168.toByte(), 1, 37), 24))
    assertEquals("10.4.0.0/16", NetworkWatch.subnet(byteArrayOf(10, 4, 200.toByte(), 9), 16))
    assertEquals("172.16.5.128/25", NetworkWatch.subnet(byteArrayOf(172.toByte(), 16, 5, 200.toByte()), 25))
    assertEquals("10.1.2.3/32", NetworkWatch.subnet(byteArrayOf(10, 1, 2, 3), 32))
    assertEquals("0.0.0.0/0", NetworkWatch.subnet(byteArrayOf(10, 1, 2, 3), 0))
    assertEquals("", NetworkWatch.subnet(ByteArray(16), 64))
    assertEquals("", NetworkWatch.subnet(byteArrayOf(10, 1, 2, 3), 33))
  }

  // ---- searching again when the network is back ----

  @Test
  fun whileHoldingANetworkThatIsNewsStartsASearchNow() {
    val long = NetworkWatch.RETRY_ON_NETWORK_MIN_MS
    // No network before, a network now.
    assertTrue(NetworkWatch.retryNow(true, NetworkWatch.NONE, homeFacts(), long))
    // The same wifi, which the system has now seen reach the internet.
    assertTrue(NetworkWatch.retryNow(true, homeFacts().copy(validated = 0), homeFacts(), long))
    // Another network.
    assertTrue(NetworkWatch.retryNow(true, homeFacts(), mobileFacts(), long))
    assertTrue(NetworkWatch.retryNow(true, null, homeFacts(), long))
    // A network after none that the system has not validated: on a
    // filtered network its check may never pass, and a route may carry.
    assertTrue(NetworkWatch.retryNow(true, NetworkWatch.NONE, homeFacts().copy(validated = 0), long))
    assertTrue(NetworkWatch.retryNow(true, NetworkWatch.NONE, homeFacts().copy(validated = -1), long))
  }

  @Test
  fun noSearchIsStartedWithoutAReason() {
    val long = NetworkWatch.RETRY_ON_NETWORK_MIN_MS
    // Not holding: connected (the engine looks after itself), or down.
    assertFalse(NetworkWatch.retryNow(false, NetworkWatch.NONE, homeFacts(), long))
    // No network.
    assertFalse(NetworkWatch.retryNow(true, homeFacts(), NetworkWatch.NONE, long))
    // The same network as before: only its metering changed, or the
    // system stopped seeing the internet through it, or still does not.
    assertFalse(NetworkWatch.retryNow(true, homeFacts(), homeFacts().copy(metered = 1), long))
    assertFalse(NetworkWatch.retryNow(true, homeFacts(), homeFacts().copy(validated = 0), long))
    assertFalse(NetworkWatch.retryNow(true, homeFacts().copy(validated = 0), homeFacts().copy(validated = 0, metered = 1), long))
    // A network that flickers does not start a pass per flicker.
    assertFalse(NetworkWatch.retryNow(true, NetworkWatch.NONE, homeFacts(), long - 1))
  }

  @Test
  fun onlyNoNetworkAtAllIsNoInternetForTheNotification() {
    assertTrue(NetworkWatch.noNetwork(NetworkWatch.NONE))
    assertFalse(NetworkWatch.noNetwork(null))
    assertFalse(NetworkWatch.noNetwork(homeFacts()))
    // Android's own check failing is not proof on a filtered network.
    assertFalse(NetworkWatch.noNetwork(homeFacts().copy(validated = 0)))
  }
}
