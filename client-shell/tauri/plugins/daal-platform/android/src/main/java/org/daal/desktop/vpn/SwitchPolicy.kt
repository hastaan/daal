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
    /**
     * The engine's automatic connect is in charge of the connection
     * (diagnostics `auto.mode`); null = the engine did not say.
     */
    val autoMode: Boolean? = null,
    /** `auto.state`: "idle", "trying", "connected", "failed"; "" = unknown. */
    val autoState: String = "",
    /** `auto.verdict`, a closed code; "" when there is none. */
    val autoVerdict: String = "",
    /**
     * `switch_back`: the last switch went to [switchBackRoute], which
     * carried nothing, and the engine went back by itself to the route
     * that was connected. [switchBackCategory] is why the switch failed
     * — by then `route_check` (and so [failedCategory]) describes the
     * route the engine went back to. [switchBackRestored]: that route
     * carried again (true), or the way back failed too (false); null
     * when there is nothing to report. "" = no such switch.
     */
    val switchBackRoute: String = "",
    val switchBackCategory: String = "",
    val switchBackRestored: Boolean? = null,
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
    // The engine has already gone back to the route that was connected
    // and THAT did not carry either: it is cooling down now, and asking
    // for it again is only refused (and would replace the reason the
    // person is shown with that refusal).
    if (engine.switchBackRoute == requested && engine.switchBackRestored == false) return AfterFailure.TearDown
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
    /**
     * The refusal code or the failure category; "" when unknown. For an
     * automatic connect ([auto]) it is the engine's verdict code.
     */
    val reason: String,
    /**
     * True when this is about an automatic connect that found no route
     * that carries; [requestedRouteId] is then "".
     */
    val auto: Boolean = false,
  )

  @JvmStatic
  fun describeFailure(requested: String, kept: String?, engine: EngineView?): SwitchNote =
    if (wasRefused(engine, requested)) {
      SwitchNote(requested, kept, "refused", engine!!.refusedCode)
    } else {
      SwitchNote(requested, kept, "failed", failureReason(requested, engine))
    }

  /**
   * Why [requested] failed its connection check. When the engine went
   * back to the old route by itself, its `route_check` is about THAT
   * route by now (ok, no category — or, if the way back failed, about
   * whichever failed last); the category of the route the person asked
   * for is the one `switch_back` kept.
   */
  private fun failureReason(requested: String, engine: EngineView?): String {
    if (engine == null) return ""
    if (engine.switchBackRoute.isNotEmpty() && engine.switchBackRoute == requested) return engine.switchBackCategory
    return engine.failedCategory
  }

  // ---------------------------------------------------------------
  // Automatic connect (engine_connect_auto): the engine picks a route,
  // tries it and moves on. The service does not choose; it starts the
  // engine's search, publishes what the engine ended on, and keeps
  // following it, because while the engine is in charge it may move to
  // another route by itself when the one in use stops carrying.
  // ---------------------------------------------------------------

  /**
   * What `engine_connect_auto` answered, cut down to what the service
   * decides on (the list of routes tried stays in the engine's
   * diagnostics for the page).
   */
  data class AutoResult(
    /** A route is connected, and [routeId] names it. */
    val connected: Boolean,
    /** The route the engine ended on; "" when none. */
    val routeId: String,
    /** The engine's closed verdict code; "" = connected on the first try. */
    val verdict: String,
    val tried: Int = 0,
    val candidates: Int = 0,
  )

  /**
   * The verdict the service reports when the engine has no automatic
   * connect to ask (an engine library older than the app). Not one of
   * the engine's codes: the page shows its general sentence for it.
   */
  const val VERDICT_UNAVAILABLE = "auto_unavailable"

  /**
   * An automatic connect ended with the engine saying nothing was
   * connected by it, and this start is still the newest request.
   *
   * The engine tried every route it could, so there is no route to "go
   * back to" by asking again — with one exception: a route that was
   * connected BEFORE the call and that the engine still carries (the
   * call was a no-op the engine answered oddly, or it failed before it
   * replaced anything). Then stay on it.
   *
   * @param lastGood the route that last passed its check on the TUN
   *                 held, or null
   * @param engine   what the engine reports now, or null
   */
  @JvmStatic
  fun afterFailedAuto(lastGood: String?, engine: EngineView?): AfterFailure {
    if (engine == null) {
      // Cannot be asked. With a route that worked, reconnecting it is
      // right whether or not it is still up (see afterFailedStart).
      return if (lastGood.isNullOrEmpty()) AfterFailure.TearDown else AfterFailure.Restore(lastGood)
    }
    val active = engine.activeRoute
    if (engine.routeRunning != false && !active.isNullOrEmpty()) {
      // Something is running. It is kept only if it is known to carry:
      // the route that was good before this call, or one the engine
      // itself calls connected.
      if (active == lastGood || engine.autoState == AUTO_CONNECTED) return AfterFailure.Keep(active)
    }
    return AfterFailure.TearDown
  }

  /** The note vpnStatus carries after an automatic connect that found nothing. */
  @JvmStatic
  fun describeAutoFailure(kept: String?, verdict: String): SwitchNote =
    SwitchNote(requestedRouteId = "", keptRouteId = kept, outcome = "failed", reason = verdict, auto = true)

  /**
   * `auto.verdict` after the engine moved off a route that had become
   * slow onto one it measured as better. The connection was never down.
   */
  const val VERDICT_MOVED_FASTER = "moved_faster"

  const val AUTO_TRYING = "trying"
  const val AUTO_CONNECTED = "connected"
  const val AUTO_FAILED = "failed"

  /** What the service does about the engine's own state while connected automatically. */
  sealed class Follow {
    /** Nothing to do. */
    object None : Follow()

    /**
     * The engine moved to [routeId] by itself and it carries: publish
     * it. [faster]: it left a route that still carried but had become
     * slow, for one it measured as clearly better (the engine's verdict
     * `moved_faster`) — not a route that failed. The service does the
     * same thing either way; the difference is what its log says, and
     * that nothing was ever down.
     */
    data class Moved(val routeId: String, val faster: Boolean = false) : Follow()

    /**
     * The engine ran out of routes: nothing is carried any more.
     * [verdict] is its closed code for why.
     */
    data class Lost(val verdict: String) : Follow()
  }

  /**
   * While an automatic connect is in charge, the engine replaces a
   * route that stopped carrying with the next one WITHOUT the service
   * asking (the service keeps the TUN; nothing is rebuilt). That is not
   * an error and must not be treated as one: the service only has to
   * notice, so that vpnStatus and the notification name the route that
   * is actually running.
   *
   * @param shown  the route the service currently reports, or null
   * @param engine what the engine reports now, or null
   */
  @JvmStatic
  fun follow(shown: String?, engine: EngineView?): Follow {
    // Unknown is never a reason to change anything.
    if (engine == null || engine.autoMode != true) return Follow.None
    val active = engine.activeRoute
    return when (engine.autoState) {
      AUTO_CONNECTED ->
        if (!active.isNullOrEmpty() && engine.routeRunning != false && active != shown) {
          Follow.Moved(active, faster = engine.autoVerdict == VERDICT_MOVED_FASTER)
        } else {
          Follow.None
        }
      // Still looking: what is shown stays until the engine has decided.
      AUTO_FAILED ->
        if (engine.routeRunning == false || active == "") Follow.Lost(engine.autoVerdict) else Follow.None
      else -> Follow.None
    }
  }

  /**
   * How long to wait before asking the engine to search again after it
   * ran out of routes while connected automatically. The first retry is
   * soon (a network that dropped for a moment); later ones back off, so
   * a phone with no network at all is not kept busy. A retry is a whole
   * pass: routes the engine is resting after a failure that ANSWERED are
   * left out, but after a pass in which nothing answered at all (no
   * usable network) the engine rests nothing, so every route is tried
   * again — at most once per [RETRY_MAX_MS].
   *
   * @param attempt 1 for the first retry
   */
  @JvmStatic
  fun retryDelayMs(attempt: Int): Long {
    val n = if (attempt < 1) 1 else attempt
    if (n >= 6) return RETRY_MAX_MS
    val d = RETRY_FIRST_MS shl (n - 1)
    return if (d > RETRY_MAX_MS) RETRY_MAX_MS else d
  }

  /**
   * Is the service HOLDING — the VPN interface up, nothing connected
   * behind it, an automatic connect in charge? That is the state after
   * the engine ran out of routes while the person was connected (the
   * service retries on a timer), and for the seconds of a first
   * automatic connect before a route is up. vpnStatus reports it so the
   * page can say that other apps have no internet meanwhile and offer
   * Disconnect; the page prefers the engine's own "trying" when it says
   * so. After a teardown the TUN is gone and this is false, whatever
   * [auto] still reads.
   */
  @JvmStatic
  fun holding(auto: Boolean, tunHeld: Boolean, connected: Boolean): Boolean = auto && tunHeld && !connected

  const val RETRY_FIRST_MS = 10_000L
  const val RETRY_MAX_MS = 300_000L
}
