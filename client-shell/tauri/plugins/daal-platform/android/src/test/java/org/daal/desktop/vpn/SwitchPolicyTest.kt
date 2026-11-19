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
  fun aRefusalOfAnotherRouteIsNotThisRoutesRefusal() {
    val other = view(active = "r1", running = true, refused = "cooldown", refusedRoute = "r9")
    assertFalse(SwitchPolicy.wasRefused(other, "r2"))
    assertTrue(SwitchPolicy.wasRefused(other, "r9"))
    assertFalse(SwitchPolicy.wasRefused(null, "r2"))
  }
}
