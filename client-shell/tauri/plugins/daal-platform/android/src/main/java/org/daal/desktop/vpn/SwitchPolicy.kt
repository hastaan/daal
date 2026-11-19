package org.daal.desktop.vpn

/**
 * The decisions DaalVpnService makes, with everything Android and
 * everything JNI taken out so they can be tested on a plain JVM
 * (src/test/.../SwitchPolicyTest.kt).
 *
 * THE RULE THESE EXIST FOR. A person connected on route A taps Connect
 * on route B. Whatever happens to B — the engine refuses it (it is
 * cooling down, revoked, needs a new file), or starts it and it carries
 * nothing — they must not end up disconnected without having asked to
 * be. The first real-phone pass did exactly that: the service had
 * already replaced A's TUN before the engine could refuse B, then tore
 * everything down and stopped itself.
 *
 * What the engine guarantees (core/abi/abi.go SetRoute, ClearRoute):
 *
 *  - a REFUSED setRoute changes nothing: the route that was connected
 *    stays connected and stays watched;
 *  - a setRoute that gets past its refusals REPLACES what was running,
 *    and if the new route then fails its connection check the engine
 *    tears it down — nothing is carried any more;
 *  - the TUN the host handed over stays usable across engine instances
 *    (each instance works on its own duplicate), so a switch needs no
 *    new TUN: the service keeps the one it has, which is what lets A
 *    keep carrying traffic right up to the moment B is accepted.
 *
 * So after a switch that did not succeed the service is in one of two
 * places, and [afterFailedStart] tells them apart from what the engine
 * reports: A is still up (keep it), or nothing is up (reconnect A).
 */
object SwitchPolicy {

  /**
   * What the engine says right now (DaalCoreBridge.engineState).
   * [activeRoute] and [routeRunning] are null when the engine did not
   * report them — "unknown", which is not the same as "nothing".
   */
  data class EngineView(
    /** Route whose instance is running; "" = none; null = unknown. */
    val activeRoute: String?,
    /** True while an engine instance is up; null = unknown. */
    val routeRunning: Boolean?,
    /** Why the last setRoute was refused ("" = it was not). */
    val refusedCode: String,
    /** The route that refusal was about. */
    val refusedRoute: String,
    /** Category of a failed connection check, else "". */
    val failedCategory: String,
  )

  /** What to do after a start that did not come up and is still the newest request. */
  sealed class AfterFailure {
    /** The engine is still carrying [routeId]. Touch nothing; stay connected on it. */
    data class Keep(val routeId: String) : AfterFailure()

    /** Nothing is carried any more. Reconnect [routeId] on the TUN already held. */
    data class Restore(val routeId: String) : AfterFailure()

    /** There is nothing to go back to. Release the TUN and stop. */
    object TearDown : AfterFailure()
  }

  /**
   * @param requested the route this start asked for (it did not come up)
   * @param lastGood  the route that last passed its connection check on
   *                  the TUN currently held, or null on a first connect
   * @param engine    what the engine reports, or null if it cannot be asked
   */
  @JvmStatic
  fun afterFailedStart(requested: String, lastGood: String?, engine: EngineView?): AfterFailure {
    // A first connect that failed: nothing was working before it.
    if (lastGood.isNullOrEmpty()) return AfterFailure.TearDown
    // The engine cannot be asked. Reconnecting what worked is right in
    // both worlds: if A was untouched this restarts it (a blip), and if
    // A is gone this brings it back.
    if (engine == null) return AfterFailure.Restore(lastGood)

    if (carries(engine, requested, lastGood)) return AfterFailure.Keep(lastGood)

    // Nothing is running. If the route that just failed IS the one that
    // was connected (a re-tap on the connected route whose check then
    // failed), asking for it again at once only meets its cooldown.
    if (requested == lastGood) return AfterFailure.TearDown
    return AfterFailure.Restore(lastGood)
  }

  /** Is the engine, by its own account, still carrying [lastGood]? */
  private fun carries(engine: EngineView, requested: String, lastGood: String): Boolean {
    if (engine.routeRunning == false) return false
    val active = engine.activeRoute
    if (active != null) return active == lastGood
    // An engine that does not report its active route. It does report
    // refusals: this request was refused, a refusal changes nothing, so
    // what ran before still runs — provided something is running.
    return engine.routeRunning == true && wasRefused(engine, requested)
  }

  /** Did the engine refuse [requested] before starting anything? */
  @JvmStatic
  fun wasRefused(engine: EngineView?, requested: String): Boolean =
    engine != null && engine.refusedCode.isNotEmpty() && engine.refusedRoute == requested

  /** One turn of the loop that cancels a start which has been superseded. */
  enum class CancelStep {
    /** The start has finished; nothing left to cancel. */
    DONE,

    /** Call the engine's cancel now. */
    CANCEL,

    /** Look again shortly. */
    WAIT,
  }

  /**
   * A start that is no longer the newest request may be blocked inside
   * the engine's connection check (seconds; minutes on a cold tor
   * route). Whoever superseded it must not wait behind that.
   *
   * The engine's cancel is clearRoute: it abandons a check in flight at
   * once — and it also stops a route that is CONNECTED. So:
   *
   *  - a STOP repeats it until the start has finished: everything is
   *    coming down anyway, and a start that has not reached setRoute yet
   *    has nothing to abandon until it does;
   *  - a NEWER START calls it only while the old start is actually
   *    inside a connection check ([checkingGen] is that start's number).
   *    Before that point the connected route is still the old, working
   *    one, and cancelling would disconnect it for a start that is about
   *    to notice by itself that it was superseded.
   *
   * @param stopping        the superseder is a stop, not a start
   * @param pendingStart    generation of the start being cancelled
   * @param finishedStart   generation of the newest start that has finished
   * @param checkingGen     generation of the start now inside setRoute, 0 if none
   */
  @JvmStatic
  fun cancelStep(stopping: Boolean, pendingStart: Int, finishedStart: Int, checkingGen: Int): CancelStep = when {
    finishedStart >= pendingStart -> CancelStep.DONE
    stopping -> CancelStep.CANCEL
    checkingGen in 1..pendingStart -> CancelStep.CANCEL
    else -> CancelStep.WAIT
  }

  /**
   * What vpnStatus reports about the last switch that did not take, so
   * the page can say "that route could not be used; you are still
   * connected through the other one" after the engine's own verdict has
   * been overwritten by the reconnect. Codes only.
   */
  data class SwitchNote(
    /** The route that was asked for and did not come up. */
    val requestedRouteId: String,
    /** The route the service stayed on / went back to; null if none. */
    val keptRouteId: String?,
    /** "refused" (never started) or "failed" (started, carried nothing). */
    val outcome: String,
    /** The refusal code or the failure category; "" when unknown. */
    val reason: String,
  )

  @JvmStatic
  fun describeFailure(requested: String, kept: String?, engine: EngineView?): SwitchNote =
    if (wasRefused(engine, requested)) {
      SwitchNote(requested, kept, "refused", engine!!.refusedCode)
    } else {
      SwitchNote(requested, kept, "failed", engine?.failedCategory ?: "")
    }
}
