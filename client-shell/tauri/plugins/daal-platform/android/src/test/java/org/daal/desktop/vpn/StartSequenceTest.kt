package org.daal.desktop.vpn

import org.daal.desktop.vpn.StartSequence.Outcome
import org.daal.desktop.vpn.SwitchPolicy.EngineView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ORDER of a start, against a fake engine that behaves the way
 * core/abi/abi.go SetRoute documents:
 *
 *  - a refused route changes nothing and records the refusal;
 *  - an accepted route replaces what was running; if it then fails its
 *    check nothing is running any more.
 *
 * The fake also models the one Android fact that matters: building a
 * TUN cuts off whatever route was using the previous one.
 */
class StartSequenceTest {

  private class Fake(
    var tun: Boolean = false,
    var good: String? = null,
    /** What the engine is carrying. */
    var carrying: String? = null,
    /** Routes the engine refuses, with the code. */
    val refuses: Map<String, String> = emptyMap(),
    /** Routes that start and then carry nothing. */
    val dead: Set<String> = emptySet(),
    val hasPrecheck: Boolean = true,
    val reportsState: Boolean = true,
    /** Becomes superseded when setRoute is called for this route. */
    val supersededDuring: String? = null,
    /** The engine's automatic connect tries these, in this order. */
    val autoOrder: List<String> = emptyList(),
    /** What it says when none of them carries. */
    val autoVerdict: String = "all_failed",
    /** False = an engine library without engine_connect_auto. */
    val hasAuto: Boolean = true,
    /** Becomes superseded (a stop's clearRoute) while connectAuto is trying. */
    val supersededDuringAuto: Boolean = false,
    /** connectAuto answers "nothing connected" without touching what runs. */
    val autoGivesUpAtOnce: Boolean = false,
    /**
     * The engine since SW-1: a switch to a route that carries nothing
     * is followed, inside the same setRoute, by the engine starting and
     * re-checking the route that was carrying. setRoute still fails.
     */
    val engineSwitchesBack: Boolean = false,
    /** …and that way back does not carry either (the old route cools down). */
    val wayBackFails: Boolean = false,
  ) : StartSequence.Host {
    val calls = mutableListOf<String>()
    var note: SwitchPolicy.SwitchNote? = null
    var published: String? = null
    var isSuperseded = false
    private var refused = ""
    private var refusedRoute = ""
    private var category = ""
    private var sbRoute = ""
    private var sbCategory = ""
    private var sbRestored: Boolean? = null
    private val cooling = mutableSetOf<String>()

    /** Did traffic stop at any point for a route that was carrying? */
    var interrupted = false

    override fun superseded() = isSuperseded
    override fun tunHeld() = tun
    override fun lastGood() = good
    override fun setLastGood(routeId: String) { good = routeId }
    override fun registerProtect(): Int { calls += "protect"; return 0 }

    override fun precheck(routeId: String): EngineView? {
      if (!hasPrecheck) return null
      calls += "precheck($routeId)"
      val code = refuses[routeId] ?: ""
      if (code.isNotEmpty()) { refused = code; refusedRoute = routeId }
      return EngineView(carrying ?: "", null, code, routeId, "")
    }

    override fun establishTun(): Outcome? {
      calls += "establishTun"
      // A new interface replaces the one the connected route is using.
      if (carrying != null) { interrupted = true; carrying = null }
      tun = true
      return null
    }

    override fun retractRefresh() { calls += "retractRefresh" }

    override fun setRoute(routeId: String): Int {
      calls += "setRoute($routeId)"
      if (supersededDuring == routeId) {
        // The canceller's clearRoute: whatever was up is down.
        isSuperseded = true
        if (carrying != null) interrupted = true
        carrying = null
        return -1
      }
      refuses[routeId]?.let { refused = it; refusedRoute = routeId; return -1 }
      if (routeId in cooling) { refused = "cooldown"; refusedRoute = routeId; return -1 }
      // Accepted: replaces what was running.
      refused = ""; refusedRoute = ""
      sbRoute = ""; sbCategory = ""; sbRestored = null
      if (carrying != null && carrying != routeId) interrupted = true
      if (routeId in dead && engineSwitchesBack && carrying != null && carrying != routeId) {
        // The engine goes back by itself. route_check is then about the
        // route it went back to; why the switch failed is in switch_back.
        sbRoute = routeId; sbCategory = "timeout"
        if (wayBackFails) {
          cooling += carrying!!
          carrying = null; category = "timeout"; sbRestored = false
        } else {
          category = ""; sbRestored = true
        }
        return -1
      }
      if (routeId in dead) { carrying = null; category = "timeout"; return -1 }
      carrying = routeId
      return 0
    }

    override fun connectAuto(): SwitchPolicy.AutoResult? {
      calls += "connectAuto"
      if (!hasAuto) return null
      if (supersededDuringAuto) {
        // The canceller's clearRoute: whatever was up is down.
        isSuperseded = true
        if (carrying != null) interrupted = true
        carrying = null
        return SwitchPolicy.AutoResult(false, "", "")
      }
      if (autoGivesUpAtOnce) return SwitchPolicy.AutoResult(false, "", autoVerdict)
      // Already connected: a no-op that names the running route.
      carrying?.let { return SwitchPolicy.AutoResult(true, it, "") }
      // Routes the engine would refuse are not candidates at all.
      val candidates = autoOrder.filter { it !in refuses }
      var tried = 0
      for (r in candidates) {
        tried++
        if (r in dead) continue
        carrying = r
        autoState = "connected"
        return SwitchPolicy.AutoResult(true, r, if (tried > 1) "moved_on" else "", tried, candidates.size)
      }
      autoState = "failed"
      return SwitchPolicy.AutoResult(false, "", autoVerdict, tried, candidates.size)
    }

    var autoState = ""
    var held = false

    override fun hold(verdict: String) {
      calls += "hold"
      held = true
      good = null; published = null
    }

    override fun engineView(): EngineView? {
      if (!reportsState) return null
      return EngineView(
        carrying ?: "", carrying != null, refused, refusedRoute, category,
        autoMode = autoState.isNotEmpty(), autoState = autoState,
        switchBackRoute = sbRoute, switchBackCategory = sbCategory, switchBackRestored = sbRestored,
      )
    }

    override fun routeIsUp(routeId: String): Outcome {
      calls += "routeIsUp($routeId)"
      if (isSuperseded) return Outcome.SUPERSEDED
      published = routeId
      return Outcome.UP
    }

    override fun teardown(why: String) {
      calls += "teardown"
      if (carrying != null) interrupted = true
      carrying = null; tun = false; good = null; published = null
    }

    override fun note(note: SwitchPolicy.SwitchNote?) { this.note = note }
    override fun log(message: String) {}

    fun did(prefix: String) = calls.any { it.startsWith(prefix) }
  }

  private fun connectedOn(route: String, f: Fake) = f.apply {
    tun = true; good = route; carrying = route; published = route
  }

  // ---- first connect ----

  @Test
  fun firstConnectBuildsTheTunThenSetsTheRoute() {
    val f = Fake()
    assertEquals(Outcome.UP, StartSequence(f).run("r1"))
    assertEquals(
      listOf("protect", "precheck(r1)", "establishTun", "setRoute(r1)", "routeIsUp(r1)"),
      f.calls,
    )
    assertEquals("r1", f.good)
    assertEquals("r1", f.published)
  }

  @Test
  fun firstConnectToARefusedRouteBuildsNoTun() {
    val f = Fake(refuses = mapOf("r1" to "cooldown"))
    assertEquals(Outcome.DOWN, StartSequence(f).run("r1"))
    assertFalse(f.did("establishTun"))
    assertFalse(f.did("setRoute"))
    assertTrue(f.did("teardown"))
    assertEquals(null, f.note) // not a switch: the engine's diagnostics say it all
  }

  @Test
  fun firstConnectThatCarriesNothingTearsDown() {
    val f = Fake(dead = setOf("r1"))
    assertEquals(Outcome.DOWN, StartSequence(f).run("r1"))
    assertEquals("teardown", f.calls.last())
    assertFalse(f.tun)
  }

  // ---- the switch: r1 connected, Connect tapped on r2 ----

  @Test
  fun switchReusesTheTunAndNeverBuildsOne() {
    val f = connectedOn("r1", Fake())
    assertEquals(Outcome.UP, StartSequence(f).run("r2"))
    assertFalse("a switch must not build a TUN", f.did("establishTun"))
    assertFalse(f.did("teardown"))
    assertEquals(
      listOf("protect", "precheck(r2)", "retractRefresh", "setRoute(r2)", "routeIsUp(r2)"),
      f.calls,
    )
    assertEquals("r2", f.carrying)
    assertEquals("r2", f.good)
    assertEquals(null, f.note)
  }

  @Test
  fun refusedSwitchLeavesTheWorkingRouteUntouched() {
    val f = connectedOn("r1", Fake(refuses = mapOf("r2" to "cooldown")))
    assertEquals(Outcome.UP, StartSequence(f).run("r2"))
    assertFalse("r1 must never stop carrying", f.interrupted)
    assertEquals("r1", f.carrying)
    assertEquals("r1", f.published)
    assertTrue(f.tun)
    // Nothing irreversible was even attempted.
    assertFalse(f.did("establishTun"))
    assertFalse(f.did("setRoute"))
    assertFalse(f.did("teardown"))
    assertFalse(f.did("retractRefresh"))
    assertEquals(SwitchPolicy.SwitchNote("r2", "r1", "refused", "cooldown"), f.note)
  }

  @Test
  fun refusedSwitchWithoutAPrecheckStillKeepsTheWorkingRoute() {
    // The fallback path on its own: attempt r2, read the refusal after.
    val f = connectedOn("r1", Fake(refuses = mapOf("r2" to "revoked"), hasPrecheck = false))
    assertEquals(Outcome.UP, StartSequence(f).run("r2"))
    assertFalse("r1 must never stop carrying", f.interrupted)
    assertEquals("r1", f.carrying)
    assertEquals("r1", f.published)
    assertFalse(f.did("establishTun"))
    assertFalse(f.did("teardown"))
    // The refresh dialer retracted for the switch is handed back.
    assertEquals(listOf("protect", "retractRefresh", "setRoute(r2)", "routeIsUp(r1)"), f.calls)
    assertEquals(SwitchPolicy.SwitchNote("r2", "r1", "refused", "revoked"), f.note)
  }

  @Test
  fun switchToARouteThatCarriesNothingGoesBackToTheOldOne() {
    val f = connectedOn("r1", Fake(dead = setOf("r2")))
    assertEquals(Outcome.UP, StartSequence(f).run("r2"))
    assertEquals("r1", f.carrying)
    assertEquals("r1", f.published)
    assertTrue(f.tun)
    assertFalse(f.did("establishTun"))
    assertFalse(f.did("teardown"))
    assertEquals(
      listOf("protect", "precheck(r2)", "retractRefresh", "setRoute(r2)", "setRoute(r1)", "routeIsUp(r1)"),
      f.calls,
    )
    // The engine's own verdict on r2 was overwritten by reconnecting
    // r1; the note is what is left to tell the page.
    assertEquals(SwitchPolicy.SwitchNote("r2", "r1", "failed", "timeout"), f.note)
  }

  @Test
  fun switchFailsAndTheEngineCannotSayWhy_stillGoesBack() {
    val f = connectedOn("r1", Fake(dead = setOf("r2"), hasPrecheck = false, reportsState = false))
    assertEquals(Outcome.UP, StartSequence(f).run("r2"))
    assertEquals("r1", f.carrying)
    assertFalse(f.did("teardown"))
  }

  @Test
  fun whenTheOldRouteCannotBeRestoredEitherItDisconnectsAndSaysSo() {
    val f = connectedOn("r1", Fake(dead = setOf("r2", "r1")))
    assertEquals(Outcome.DOWN, StartSequence(f).run("r2"))
    assertEquals("teardown", f.calls.last())
    assertFalse(f.tun)
    assertEquals(SwitchPolicy.SwitchNote("r2", null, "failed", "timeout"), f.note)
  }

  // ---- superseded: undo nothing, the newer request decides ----

  // ---- the engine that goes back by itself (SW-1) ----

  @Test
  fun whenTheEngineWentBackByItselfTheNoteStillSaysWhyTheSwitchFailed() {
    val f = connectedOn("r1", Fake(dead = setOf("r2"), engineSwitchesBack = true))
    assertEquals(Outcome.UP, StartSequence(f).run("r2"))
    // The engine is on r1 again: nothing to restore, nothing torn down.
    assertEquals(1, f.calls.count { it.startsWith("setRoute(") })
    assertFalse(f.did("teardown"))
    assertEquals("r1", f.published)
    // route_check is r1's by now (ok, no category). The reason is r2's.
    assertEquals(SwitchPolicy.SwitchNote("r2", "r1", "failed", "timeout"), f.note)
  }

  @Test
  fun whenTheEnginesOwnWayBackFailedTheServiceDoesNotAskForTheOldRouteAgain() {
    val f = connectedOn("r1", Fake(dead = setOf("r2"), engineSwitchesBack = true, wayBackFails = true))
    assertEquals(Outcome.DOWN, StartSequence(f).run("r2"))
    // r1 is cooling down: a second setRoute(r1) would only be refused,
    // and its refusal would replace the reason the person is shown.
    assertFalse(f.did("setRoute(r1)"))
    assertTrue(f.did("teardown"))
    assertEquals(SwitchPolicy.SwitchNote("r2", null, "failed", "timeout"), f.note)
  }

  @Test
  fun supersededDuringTheCheckUndoesNothing() {
    val f = connectedOn("r1", Fake(supersededDuring = "r2"))
    assertEquals(Outcome.SUPERSEDED, StartSequence(f).run("r2"))
    assertFalse(f.did("teardown"))
    assertFalse(f.did("routeIsUp"))
    assertEquals(1, f.calls.count { it.startsWith("setRoute") }) // no restore attempt
    assertTrue("the TUN stays for the newer start", f.tun)
    assertEquals("r1", f.good)
  }

  @Test
  fun supersededBeforeItBeginsTouchesNothing() {
    val f = connectedOn("r1", Fake()).apply { isSuperseded = true }
    assertEquals(Outcome.SUPERSEDED, StartSequence(f).run("r2"))
    assertTrue(f.calls.isEmpty())
  }

  @Test
  fun theStartAfterACancelledSwitchRestoresTheLastWorkingRouteIfRefused() {
    // r1 connected; a switch to r2 was cancelled mid-check by a newer
    // start for r3 — by then the engine had already replaced r1. r3 is
    // refused. The person must end up back on r1, not on nothing.
    val f = Fake(tun = true, good = "r1", carrying = null, refuses = mapOf("r3" to "cooldown"))
    assertEquals(Outcome.UP, StartSequence(f).run("r3"))
    assertEquals("r1", f.carrying)
    assertEquals("r1", f.published)
    assertFalse(f.did("establishTun"))
    assertFalse(f.did("teardown"))
  }

  // ---- the note about a switch that did not take ----

  @Test
  fun aNewStartForgetsTheNoteOfAnOlderSwitchBeforeItsCheckBegins() {
    // r1 connected; an earlier switch to r2 failed and left its note.
    // The person taps r2 again. The page reads the note to answer a
    // tap, so the OLD note must be gone before this start blocks in
    // its connection check — otherwise the new tap is answered
    // "failed" by the old attempt while the new one is still running.
    val f = connectedOn("r1", Fake(supersededDuring = "r2"))
    f.note = SwitchPolicy.SwitchNote("r2", "r1", "failed", "timeout")
    assertEquals(Outcome.SUPERSEDED, StartSequence(f).run("r2"))
    assertTrue(f.did("setRoute(r2)"))
    assertEquals(null, f.note)
  }

  @Test
  fun aStartThatWasSupersededBeforeItBeganLeavesTheNoteAlone() {
    val f = connectedOn("r1", Fake()).apply { isSuperseded = true }
    val old = SwitchPolicy.SwitchNote("r2", "r1", "failed", "timeout")
    f.note = old
    assertEquals(Outcome.SUPERSEDED, StartSequence(f).run("r3"))
    assertEquals(old, f.note)
  }

  // ---- automatic connect: no route named, the engine picks ----

  private val four = listOf("r1", "r2", "r3", "r4")

  @Test
  fun autoBuildsTheTunThenAsksTheEngineToPick() {
    val f = Fake(autoOrder = four)
    assertEquals(Outcome.UP, StartSequence(f).runAuto())
    // No pre-check and no setRoute: the service names no route.
    assertEquals(listOf("protect", "establishTun", "connectAuto", "routeIsUp(r1)"), f.calls)
    assertEquals("r1", f.good)
    assertEquals("r1", f.published)
    assertEquals(null, f.note)
  }

  @Test
  fun autoPublishesTheRouteTheEngineEndedOnNotTheFirstOne() {
    val f = Fake(autoOrder = four, dead = setOf("r1", "r2"), refuses = mapOf("r3" to "cooldown"))
    assertEquals(Outcome.UP, StartSequence(f).runAuto())
    assertEquals("r4", f.carrying)
    assertEquals("r4", f.good)
    assertEquals("r4", f.published)
    assertFalse(f.did("teardown"))
    // Connected: nothing is left to explain in vpnStatus.
    assertEquals(null, f.note)
  }

  @Test
  fun autoThatFindsNoRouteReleasesEverythingAndLeavesTheVerdict() {
    val f = Fake(autoOrder = four, dead = four.toSet(), autoVerdict = "network_down")
    assertEquals(Outcome.DOWN, StartSequence(f).runAuto())
    assertEquals("teardown", f.calls.last())
    assertFalse(f.tun)
    assertFalse(f.did("routeIsUp"))
    assertFalse(f.did("hold"))
    assertEquals(SwitchPolicy.SwitchNote("", null, "failed", "network_down", auto = true), f.note)
  }

  @Test
  fun autoWithNothingImportedSaysSo() {
    val f = Fake(autoOrder = emptyList(), autoVerdict = "no_routes")
    assertEquals(Outcome.DOWN, StartSequence(f).runAuto())
    assertEquals("no_routes", f.note?.reason)
    assertFalse(f.tun)
  }

  @Test
  fun autoAnswerWithoutAVerdictIsReportedAsTheGeneralOne() {
    val f = Fake(autoOrder = four, dead = four.toSet(), autoVerdict = "")
    assertEquals(Outcome.DOWN, StartSequence(f).runAuto())
    assertEquals("all_failed", f.note?.reason)
  }

  @Test
  fun autoWhileConnectedChangesNothing() {
    val f = connectedOn("r2", Fake(autoOrder = four))
    assertEquals(Outcome.UP, StartSequence(f).runAuto())
    assertFalse("r2 must never stop carrying", f.interrupted)
    assertFalse(f.did("establishTun"))
    assertFalse(f.did("teardown"))
    assertFalse(f.did("setRoute"))
    // The engine's own fetches stay on the route that stays.
    assertFalse(f.did("retractRefresh"))
    assertEquals("r2", f.published)
    assertEquals(null, f.note)
  }

  @Test
  fun autoThatGivesUpWhileARouteStillCarriesStaysOnIt() {
    val f = connectedOn("r1", Fake(autoGivesUpAtOnce = true, autoVerdict = "all_cooling_down"))
    assertEquals(Outcome.UP, StartSequence(f).runAuto())
    assertFalse("r1 must never stop carrying", f.interrupted)
    assertFalse(f.did("teardown"))
    assertTrue(f.tun)
    assertEquals("r1", f.published)
    assertEquals(SwitchPolicy.SwitchNote("", "r1", "failed", "all_cooling_down", auto = true), f.note)
  }

  @Test
  fun aStopCancelsAnAutoInFlightAndNothingIsUndoneByIt() {
    val f = Fake(autoOrder = four, supersededDuringAuto = true)
    assertEquals(Outcome.SUPERSEDED, StartSequence(f).runAuto())
    // The stop's own teardown is queued behind this start.
    assertFalse(f.did("teardown"))
    assertFalse(f.did("routeIsUp"))
    assertFalse(f.did("hold"))
    assertEquals(null, f.note)
  }

  @Test
  fun autoSupersededBeforeItBeginsDoesNothing() {
    val f = Fake(autoOrder = four).apply { isSuperseded = true }
    assertEquals(Outcome.SUPERSEDED, StartSequence(f).runAuto())
    assertTrue(f.calls.isEmpty())
  }

  @Test
  fun autoSupersededJustAfterTheEngineConnectedPublishesNothing() {
    // routeIsUp is where the service notices (it returns SUPERSEDED).
    val inner = Fake(autoOrder = four)
    val host = object : StartSequence.Host by inner {
      override fun routeIsUp(routeId: String): Outcome { inner.isSuperseded = true; return Outcome.SUPERSEDED }
    }
    assertEquals(Outcome.SUPERSEDED, StartSequence(host).runAuto())
    assertFalse(inner.did("teardown"))
    assertEquals(null, inner.published)
  }

  @Test
  fun autoWithAnEngineThatCannotBeAskedBuildsNoTun() {
    // A start by the system (always-on VPN, restart after a kill) in a
    // process where the engine is not loaded.
    val f = Fake(autoOrder = four, reportsState = false, hasAuto = false)
    assertEquals(Outcome.DOWN, StartSequence(f).runAuto())
    assertFalse("no TUN for an engine that cannot choose", f.did("establishTun"))
    assertFalse(f.did("connectAuto"))
    assertFalse(f.tun)
    // Nobody asked a question this would answer.
    assertEquals(null, f.note)
  }

  @Test
  fun autoOnAnEngineWithoutTheCallReleasesTheTunAndSaysUnavailable() {
    val f = Fake(autoOrder = four, hasAuto = false)
    assertEquals(Outcome.DOWN, StartSequence(f).runAuto())
    assertEquals("teardown", f.calls.last())
    assertFalse(f.tun)
    assertEquals(
      SwitchPolicy.SwitchNote("", null, "failed", SwitchPolicy.VERDICT_UNAVAILABLE, auto = true),
      f.note,
    )
  }

  @Test
  fun autoWithNoAnswerGoesBackToTheRouteThatWorked() {
    // Connected on r1, the engine can be asked nothing at all: the
    // same rule as a failed switch — reconnect what worked.
    val f = connectedOn("r1", Fake(hasAuto = false, reportsState = false, hasPrecheck = false))
    assertEquals(Outcome.UP, StartSequence(f).runAuto())
    assertEquals(listOf("protect", "connectAuto", "setRoute(r1)", "routeIsUp(r1)"), f.calls)
    assertEquals("r1", f.published)
    assertFalse(f.did("teardown"))
  }

  // ---- the service's own retry, after the engine ran out of routes ----

  /** The TUN is held, nothing is connected (the state `hold` leaves). */
  private fun holding(f: Fake) = f.apply {
    tun = true; good = null; carrying = null; published = null
    note = SwitchPolicy.describeAutoFailure(null, "network_down")
  }

  @Test
  fun reconnectThatFindsNoRouteKeepsTheTun() {
    val f = holding(Fake(autoOrder = four, dead = four.toSet(), autoVerdict = "network_down"))
    assertEquals(Outcome.HOLDING, StartSequence(f).runAuto(reconnect = true))
    assertFalse("the TUN must stay: the person did not disconnect", f.did("teardown"))
    assertFalse(f.did("establishTun"))
    assertTrue(f.tun)
    assertTrue(f.did("hold"))
    assertEquals(null, f.published)
    assertEquals(SwitchPolicy.SwitchNote("", null, "failed", "network_down", auto = true), f.note)
  }

  @Test
  fun reconnectThatFindsARouteIsUpAgainOnTheSameTun() {
    val f = holding(Fake(autoOrder = four, dead = setOf("r1")))
    assertEquals(Outcome.UP, StartSequence(f).runAuto(reconnect = true))
    assertEquals(listOf("protect", "connectAuto", "routeIsUp(r2)"), f.calls)
    assertEquals("r2", f.published)
    assertEquals("r2", f.good)
    assertEquals(null, f.note)
  }

  @Test
  fun reconnectKeepsTheReasonVisibleWhileItTries() {
    // Superseded mid-way: the note about why the person is not
    // connected was never wiped by the retry itself.
    val f = holding(Fake(autoOrder = four, supersededDuringAuto = true))
    assertEquals(Outcome.SUPERSEDED, StartSequence(f).runAuto(reconnect = true))
    assertEquals("network_down", f.note?.reason)
  }

  @Test
  fun aRequestByThePersonClearsAnOlderNoteAtOnce() {
    val f = holding(Fake(autoOrder = four, supersededDuringAuto = true))
    assertEquals(Outcome.SUPERSEDED, StartSequence(f).runAuto(reconnect = false))
    assertEquals(null, f.note)
  }

  @Test
  fun reconnectWithAnEngineThatIsGoneLetsGo() {
    // Retrying an engine that cannot answer would hold the TUN shut
    // for ever.
    val f = holding(Fake(hasAuto = false))
    assertEquals(Outcome.DOWN, StartSequence(f).runAuto(reconnect = true))
    assertEquals("teardown", f.calls.last())
    assertFalse(f.tun)
  }

  @Test
  fun aPersonsAutoThatFailsWhileHoldingLetsGoOfTheTun() {
    // Connect pressed while the service was holding: this is a request
    // by a person, and its failure is answered, not retried silently.
    val f = holding(Fake(autoOrder = four, dead = four.toSet(), autoVerdict = "all_cooling_down"))
    assertEquals(Outcome.DOWN, StartSequence(f).runAuto())
    assertFalse(f.tun)
    assertEquals("all_cooling_down", f.note?.reason)
  }
}
