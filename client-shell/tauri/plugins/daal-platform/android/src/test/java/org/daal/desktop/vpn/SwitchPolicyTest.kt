package org.daal.desktop.vpn

import org.daal.desktop.vpn.SwitchPolicy.AfterFailure
import org.daal.desktop.vpn.SwitchPolicy.CancelStep
import org.daal.desktop.vpn.SwitchPolicy.EngineView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for the decisions DaalVpnService makes around a route
 * switch. No Android, no engine: `./gradlew
 * :tauri-plugin-daal-platform:testDebugUnitTest` from
 * src-tauri/gen/android.
 *
 * The scenario names are the ones from the first real-phone pass:
 * connected on r1, Connect tapped on r2.
 */
class SwitchPolicyTest {

  private fun view(
    active: String? = "",
    running: Boolean? = false,
    refused: String = "",
    refusedRoute: String = "",
    category: String = "",
  ) = EngineView(active, running, refused, refusedRoute, category)

  // ---- a switch that is REFUSED must not cost the working route ----

  @Test
  fun refusedSwitchKeepsTheConnectedRoute() {
    // r2 is cooling down: the engine refused it and touched nothing.
    val engine = view(active = "r1", running = true, refused = "cooldown", refusedRoute = "r2")
    assertEquals(AfterFailure.Keep("r1"), SwitchPolicy.afterFailedStart("r2", "r1", engine))
  }

  @Test
  fun refusedByPrecheckKeepsTheConnectedRoute() {
    // The pre-check's view: it knows the active route and the refusal,
    // not whether an instance is running.
    val engine = view(active = "r1", running = null, refused = "revoked", refusedRoute = "r2")
    assertEquals(AfterFailure.Keep("r1"), SwitchPolicy.afterFailedStart("r2", "r1", engine))
  }

  @Test
  fun refusedReTapOnTheConnectedRouteKeepsIt() {
    val engine = view(active = "r1", running = true, refused = "expired", refusedRoute = "r1")
    assertEquals(AfterFailure.Keep("r1"), SwitchPolicy.afterFailedStart("r1", "r1", engine))
  }

  // ---- a switch that STARTED and failed: the old route is gone, go back ----

  @Test
  fun failedSwitchGoesBackToTheRouteThatWorked() {
    // The engine replaced r1 with r2, r2 carried nothing, the engine
    // tore it down: nothing is running.
    val engine = view(active = "", running = false, category = "timeout")
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedStart("r2", "r1", engine))
  }

  @Test
  fun refusedSwitchAfterTheOldRouteWasLostGoesBackToIt() {
    // r2 was refused, but r1 is not running any more (an earlier
    // superseded switch was cancelled after it had replaced r1).
    val engine = view(active = "", running = false, refused = "cooldown", refusedRoute = "r2")
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedStart("r2", "r1", engine))
    val pre = view(active = "", running = null, refused = "cooldown", refusedRoute = "r2")
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedStart("r2", "r1", pre))
  }

  @Test
  fun engineCarryingSomeOtherRouteIsNotMistakenForTheOldOne() {
    val engine = view(active = "r3", running = true)
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedStart("r2", "r1", engine))
  }

  @Test
  fun activeRouteNamedButNothingRunningIsNotKept() {
    val engine = view(active = "r1", running = false)
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedStart("r2", "r1", engine))
  }

  @Test
  fun reTapOnTheConnectedRouteThatThenFailsDisconnects() {
    // Asking for r1 again at once would only meet its cooldown.
    val engine = view(active = "", running = false, category = "timeout")
    assertEquals(AfterFailure.TearDown, SwitchPolicy.afterFailedStart("r1", "r1", engine))
  }

  // ---- first connect: nothing to keep ----

  @Test
  fun failedFirstConnectTearsDown() {
    val refused = view(refused = "cooldown", refusedRoute = "r1")
    assertEquals(AfterFailure.TearDown, SwitchPolicy.afterFailedStart("r1", null, refused))
    assertEquals(AfterFailure.TearDown, SwitchPolicy.afterFailedStart("r1", "", refused))
    assertEquals(AfterFailure.TearDown, SwitchPolicy.afterFailedStart("r1", null, null))
  }

  // ---- the engine cannot say: the fallback is correct on its own ----

  @Test
  fun unknownEngineStateReconnectsWhatWorked() {
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedStart("r2", "r1", null))
  }

  @Test
  fun engineWithoutActiveRouteFieldUsesTheRefusal() {
    // An engine that reports refusals and "running" but not which route.
    val refused = view(active = null, running = true, refused = "cooldown", refusedRoute = "r2")
    assertEquals(AfterFailure.Keep("r1"), SwitchPolicy.afterFailedStart("r2", "r1", refused))
    // Running, but this request was not the one refused: do not assume.
    val stale = view(active = null, running = true, refused = "cooldown", refusedRoute = "r9")
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedStart("r2", "r1", stale))
    val nothing = view(active = null, running = null)
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedStart("r2", "r1", nothing))
  }

  // ---- cancelling a superseded start ----

  @Test
  fun stopCancelsUntilTheStartHasFinished() {
    // Start 5 is pending; a stop repeats the cancel whether or not the
    // start has reached its connection check yet.
    assertEquals(CancelStep.CANCEL, SwitchPolicy.cancelStep(true, 5, 4, 0))
    assertEquals(CancelStep.CANCEL, SwitchPolicy.cancelStep(true, 5, 4, 5))
    assertEquals(CancelStep.DONE, SwitchPolicy.cancelStep(true, 5, 5, 0))
  }

  @Test
  fun newerStartCancelsACheckInFlightInsteadOfWaitingBehindIt() {
    // Start 5 is inside setRoute when start 6 arrives.
    assertEquals(CancelStep.CANCEL, SwitchPolicy.cancelStep(false, 5, 4, 5))
    // An even older start (4) is the one checking: also superseded.
    assertEquals(CancelStep.CANCEL, SwitchPolicy.cancelStep(false, 5, 3, 4))
  }

  @Test
  fun newerStartDoesNotCancelBeforeTheOldStartIsChecking() {
    // Start 5 has not reached setRoute: the connected route is still
    // the old working one, and the engine's cancel would disconnect it.
    assertEquals(CancelStep.WAIT, SwitchPolicy.cancelStep(false, 5, 4, 0))
  }

  @Test
  fun newerStartNeverCancelsItsOwnCheck() {
    // Start 5 has finished; whatever is checking now (6) is the newer
    // start itself.
    assertEquals(CancelStep.DONE, SwitchPolicy.cancelStep(false, 5, 5, 6))
    // Even if "finished" has not been published yet, a check numbered
    // above the start being cancelled is not that start's.
    assertEquals(CancelStep.WAIT, SwitchPolicy.cancelStep(false, 5, 4, 6))
  }

  // ---- what the page is told afterwards ----

  @Test
  fun noteSaysRefusedOrFailedWithAClosedCode() {
    val refused = view(active = "r1", running = true, refused = "cooldown", refusedRoute = "r2")
    assertEquals(
      SwitchPolicy.SwitchNote("r2", "r1", "refused", "cooldown"),
      SwitchPolicy.describeFailure("r2", "r1", refused),
    )
    val failed = view(active = "", running = false, category = "timeout")
    assertEquals(
      SwitchPolicy.SwitchNote("r2", "r1", "failed", "timeout"),
      SwitchPolicy.describeFailure("r2", "r1", failed),
    )
    assertEquals(
      SwitchPolicy.SwitchNote("r2", null, "failed", ""),
      SwitchPolicy.describeFailure("r2", null, null),
    )
  }

  @Test
  fun afterTheEnginesOwnSwitchBackTheNoteCarriesTheFailedRoutesCategory() {
    // The engine went back to r1 and re-proved it: route_check is ok,
    // its category "". Why r2 failed is in switch_back.
    val back = view(active = "r1", running = true)
      .copy(switchBackRoute = "r2", switchBackCategory = "udp_no_reply", switchBackRestored = true)
    assertEquals(AfterFailure.Keep("r1"), SwitchPolicy.afterFailedStart("r2", "r1", back))
    assertEquals(
      SwitchPolicy.SwitchNote("r2", "r1", "failed", "udp_no_reply"),
      SwitchPolicy.describeFailure("r2", "r1", back),
    )
    // A switch_back about some OTHER, earlier switch says nothing here.
    val stale = view(active = "", running = false, category = "timeout")
      .copy(switchBackRoute = "r7", switchBackCategory = "udp_no_reply", switchBackRestored = true)
    assertEquals("timeout", SwitchPolicy.describeFailure("r2", "r1", stale).reason)
  }

  @Test
  fun whenTheEnginesWayBackFailedTooThereIsNothingToRestore() {
    val gone = view(active = "", running = false, category = "timeout")
      .copy(switchBackRoute = "r2", switchBackCategory = "tcp_reset", switchBackRestored = false)
    assertEquals(AfterFailure.TearDown, SwitchPolicy.afterFailedStart("r2", "r1", gone))
    assertEquals("tcp_reset", SwitchPolicy.describeFailure("r2", null, gone).reason)
    // An engine that reports no switch_back (older library): as before.
    assertEquals(
      AfterFailure.Restore("r1"),
      SwitchPolicy.afterFailedStart("r2", "r1", view(active = "", running = false, category = "timeout")),
    )
  }

  @Test
  fun holdingIsATunWithNothingBehindItUnderAnAutomaticConnect() {
    assertTrue(SwitchPolicy.holding(auto = true, tunHeld = true, connected = false))
    // Connected: not holding. Torn down (no TUN): not holding, even
    // though the automatic flag outlives the service instance.
    assertFalse(SwitchPolicy.holding(auto = true, tunHeld = true, connected = true))
    assertFalse(SwitchPolicy.holding(auto = true, tunHeld = false, connected = false))
    // A route picked by hand that failed is torn down or restored,
    // never held.
    assertFalse(SwitchPolicy.holding(auto = false, tunHeld = true, connected = false))
  }

  @Test
  fun aRefusalOfAnotherRouteIsNotThisRoutesRefusal() {
    val other = view(active = "r1", running = true, refused = "cooldown", refusedRoute = "r9")
    assertFalse(SwitchPolicy.wasRefused(other, "r2"))
    assertTrue(SwitchPolicy.wasRefused(other, "r9"))
    assertFalse(SwitchPolicy.wasRefused(null, "r2"))
  }

  // ---- automatic connect ----

  private fun auto(
    active: String? = "",
    running: Boolean? = false,
    mode: Boolean? = true,
    state: String = "",
    verdict: String = "",
  ) = EngineView(active, running, "", "", "", autoMode = mode, autoState = state, autoVerdict = verdict)

  @Test
  fun failedAutoWithNothingRunningTearsDown() {
    assertEquals(AfterFailure.TearDown, SwitchPolicy.afterFailedAuto(null, auto(state = "failed")))
    // Even with a route that was good before: the engine tried every
    // route, that one included, and none carries.
    assertEquals(AfterFailure.TearDown, SwitchPolicy.afterFailedAuto("r1", auto(state = "failed")))
  }

  @Test
  fun failedAutoKeepsTheRouteThatWasConnectedAndStillIs() {
    assertEquals(
      AfterFailure.Keep("r1"),
      SwitchPolicy.afterFailedAuto("r1", auto(active = "r1", running = true, mode = false)),
    )
    // Running unknown, active known: still the same route.
    assertEquals(
      AfterFailure.Keep("r1"),
      SwitchPolicy.afterFailedAuto("r1", auto(active = "r1", running = null)),
    )
  }

  @Test
  fun failedAutoDoesNotKeepARouteThatIsOnlyBeingTried() {
    // An instance is up for r3 but nothing says it carries.
    assertEquals(
      AfterFailure.TearDown,
      SwitchPolicy.afterFailedAuto("r1", auto(active = "r3", running = true, state = "trying")),
    )
    // The engine itself calls it connected: keep that one.
    assertEquals(
      AfterFailure.Keep("r3"),
      SwitchPolicy.afterFailedAuto(null, auto(active = "r3", running = true, state = "connected")),
    )
  }

  @Test
  fun failedAutoWithAnEngineThatCannotBeAsked() {
    assertEquals(AfterFailure.TearDown, SwitchPolicy.afterFailedAuto(null, null))
    assertEquals(AfterFailure.Restore("r1"), SwitchPolicy.afterFailedAuto("r1", null))
  }

  @Test
  fun autoNoteNamesNoRouteAndCarriesTheVerdict() {
    val n = SwitchPolicy.describeAutoFailure(null, "udp_blocked_here")
    assertEquals("", n.requestedRouteId)
    assertEquals(null, n.keptRouteId)
    assertEquals("failed", n.outcome)
    assertEquals("udp_blocked_here", n.reason)
    assertTrue(n.auto)
    // A note about a route picked by hand is not an automatic one.
    assertFalse(SwitchPolicy.describeFailure("r2", "r1", view(active = "r1", running = true)).auto)
  }

  // ---- following the engine while it is in charge ----

  @Test
  fun engineThatMovedByItselfIsFollowedNotTreatedAsAnError() {
    val engine = auto(active = "r3", running = true, state = "connected", verdict = "moved_on")
    assertEquals(SwitchPolicy.Follow.Moved("r3"), SwitchPolicy.follow("r1", engine))
    // Holding (nothing shown) and the engine is up again.
    assertEquals(SwitchPolicy.Follow.Moved("r3"), SwitchPolicy.follow(null, engine))
  }

  @Test
  fun sameRouteIsNothingToFollow() {
    val engine = auto(active = "r1", running = true, state = "connected")
    assertEquals(SwitchPolicy.Follow.None, SwitchPolicy.follow("r1", engine))
  }

  @Test
  fun whileTheEngineIsStillTryingWhatIsShownStays() {
    // r1 stopped carrying, the engine is checking r2: not yet a move,
    // and not a loss.
    val engine = auto(active = "r2", running = true, state = "trying")
    assertEquals(SwitchPolicy.Follow.None, SwitchPolicy.follow("r1", engine))
    assertEquals(SwitchPolicy.Follow.None, SwitchPolicy.follow("r1", auto(active = "", running = false, state = "trying")))
  }

  @Test
  fun engineOutOfRoutesIsALossWithItsVerdict() {
    val engine = auto(active = "", running = false, state = "failed", verdict = "network_down")
    assertEquals(SwitchPolicy.Follow.Lost("network_down"), SwitchPolicy.follow("r1", engine))
    // "failed" while an instance is still said to run is not acted on.
    assertEquals(
      SwitchPolicy.Follow.None,
      SwitchPolicy.follow("r1", auto(active = "r1", running = true, state = "failed")),
    )
  }

  @Test
  fun aRoutePickedByHandIsNeverFollowedAway() {
    // Mode off (manual) or unknown (an engine that does not report it):
    // the engine does not move by itself, and an odd reading must not
    // change what the service says.
    assertEquals(
      SwitchPolicy.Follow.None,
      SwitchPolicy.follow("r1", auto(active = "r2", running = true, mode = false, state = "connected")),
    )
    assertEquals(
      SwitchPolicy.Follow.None,
      SwitchPolicy.follow("r1", auto(active = "", running = false, mode = null, state = "failed")),
    )
    assertEquals(SwitchPolicy.Follow.None, SwitchPolicy.follow("r1", null))
    // A connected state that names no route moves nothing.
    assertEquals(
      SwitchPolicy.Follow.None,
      SwitchPolicy.follow("r1", auto(active = null, running = null, state = "connected")),
    )
  }

  @Test
  fun retriesBackOffAndAreBounded() {
    assertEquals(10_000L, SwitchPolicy.retryDelayMs(1))
    assertEquals(20_000L, SwitchPolicy.retryDelayMs(2))
    assertEquals(40_000L, SwitchPolicy.retryDelayMs(3))
    assertEquals(160_000L, SwitchPolicy.retryDelayMs(5))
    assertEquals(300_000L, SwitchPolicy.retryDelayMs(6))
    assertEquals(300_000L, SwitchPolicy.retryDelayMs(1000))
    assertEquals(10_000L, SwitchPolicy.retryDelayMs(0))
    var last = 0L
    for (i in 1..40) {
      val d = SwitchPolicy.retryDelayMs(i)
      assertTrue(d >= last)
      last = d
    }
  }

  // ---- cancelling an automatic connect uses the same discipline ----

  @Test
  fun aStopOrANewerStartCancelsAnAutoInsideTheEngine() {
    // Start 7 is an automatic connect inside connectAuto (checkingGen).
    assertEquals(CancelStep.CANCEL, SwitchPolicy.cancelStep(stopping = true, pendingStart = 7, finishedStart = 6, checkingGen = 7))
    assertEquals(CancelStep.CANCEL, SwitchPolicy.cancelStep(stopping = false, pendingStart = 7, finishedStart = 6, checkingGen = 7))
    // A newer start does not clear the route before the older one is in
    // the engine: until then the connected route is still the old one.
    assertEquals(CancelStep.WAIT, SwitchPolicy.cancelStep(stopping = false, pendingStart = 7, finishedStart = 6, checkingGen = 0))
    assertEquals(CancelStep.DONE, SwitchPolicy.cancelStep(stopping = true, pendingStart = 7, finishedStart = 7, checkingGen = 0))
  }
}
