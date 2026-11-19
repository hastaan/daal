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
  ) : StartSequence.Host {
    val calls = mutableListOf<String>()
    var note: SwitchPolicy.SwitchNote? = null
    var published: String? = null
    var isSuperseded = false
    private var refused = ""
    private var refusedRoute = ""
    private var category = ""

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
      // Accepted: replaces what was running.
      refused = ""; refusedRoute = ""
      if (carrying != null && carrying != routeId) interrupted = true
      if (routeId in dead) { carrying = null; category = "timeout"; return -1 }
      carrying = routeId
      return 0
    }

    override fun engineView(): EngineView? {
      if (!reportsState) return null
      return EngineView(carrying ?: "", carrying != null, refused, refusedRoute, category)
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
}
