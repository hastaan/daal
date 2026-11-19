package org.daal.desktop.vpn

/**
 * What DaalVpnService does, in order, when it is asked to connect a
 * route — written against [Host] instead of Android and the engine so
 * the ORDER can be tested on a plain JVM (StartSequenceTest), because
 * the order is the bug this replaced:
 *
 *   before:  build a new TUN → hand it to the engine → setRoute(B)
 *            → B refused → clearRoute, clearTunFd, stop the service.
 *            Building the TUN had already cut route A off, so a switch
 *            to a route that was cooling down ended in a silent
 *            disconnect.
 *
 *   now:     ask the engine whether B would be refused → (only when no
 *            TUN is held) build one → setRoute(B) → and when B does not
 *            come up, [SwitchPolicy.afterFailedStart] decides between
 *            staying on A, reconnecting A, and — with nothing to go back
 *            to — tearing down.
 *
 * A switch never builds a TUN and never releases one unless it ends
 * with nothing connected. Route A carries traffic until the engine
 * itself replaces it with B.
 *
 * Runs on the service's control thread; one start at a time.
 */
class StartSequence(private val host: Host) {

  /** How a start ended. */
  enum class Outcome {
    /** A route is connected (the one asked for, or the one kept). */
    UP,

    /** Nothing is connected and everything has been released. */
    DOWN,

    /**
     * A stop or a newer start took over. NOTHING is undone: a stop has
     * queued its teardown behind this start, and a newer start
     * continues from the state this one leaves (the TUN, and whatever
     * the engine is carrying).
     */
    SUPERSEDED,

    /**
     * Automatic reconnect only: nothing is connected, but the TUN is
     * KEPT and the service will ask the engine to search again. The
     * person was connected and did not ask to be disconnected; letting
     * go of the TUN here would put their traffic back on the open
     * network without a word, so it stays closed until a route carries
     * again or they disconnect.
     */
    HOLDING,
  }

  /** Everything the sequence needs from the service and the engine. */
  interface Host {
    /** A stop or a newer start has been requested since this one. */
    fun superseded(): Boolean

    /** The engine holds a TUN this service built and has not released. */
    fun tunHeld(): Boolean

    /** The route that last passed its connection check on that TUN. */
    fun lastGood(): String?

    /** The engine is carrying [routeId] now. */
    fun setLastGood(routeId: String)

    /** Wire the protect callback; returns the engine's code. */
    fun registerProtect(): Int

    /** `engine_route_precheck`, or null when it cannot be asked. */
    fun precheck(routeId: String): SwitchPolicy.EngineView?

    /**
     * Build the TUN and hand it to the engine. Null on success, else
     * how the start ends (DOWN, or SUPERSEDED if that happened while
     * the interface was being built).
     */
    fun establishTun(): Outcome?

    /** Take the engine's own fetches off the route about to be replaced. */
    fun retractRefresh()

    /**
     * `engine_set_route`: blocks for the connection check. 0 = the
     * route is connected. Anything else = it is not; [superseded] says
     * whether that was a cancellation.
     */
    fun setRoute(routeId: String): Int

    /**
     * `engine_connect_auto`: the engine picks among every usable route,
     * tries them in order and keeps the first that carries. Blocks for
     * all of it; a stop or a newer start makes it return promptly
     * ([superseded] then says so). Null when the engine cannot be asked
     * or has no such call.
     */
    fun connectAuto(): SwitchPolicy.AutoResult?

    /**
     * Nothing is connected but the TUN stays: stop saying a route is
     * up. A retry of the automatic connect follows.
     */
    fun hold(verdict: String)

    /** What the engine says about the connection now, or null. */
    fun engineView(): SwitchPolicy.EngineView?

    /**
     * The engine is carrying [routeId]: publish it (status,
     * notification, tunnel refresh, scheduler pump). Returns UP, or
     * SUPERSEDED when a stop or newer start arrived first.
     */
    fun routeIsUp(routeId: String): Outcome

    /** Release everything: tunnel refresh, route, TUN. */
    fun teardown(why: String)

    /** Remember (or forget) the last switch that did not take. */
    fun note(note: SwitchPolicy.SwitchNote?)

    fun log(message: String)
  }

  fun run(routeId: String): Outcome {
    host.log("begin route=$routeId tun_held=${host.tunHeld()} last_good=${host.lastGood() ?: "-"}")
    if (host.superseded()) {
      host.log("superseded before it began")
      return Outcome.SUPERSEDED
    }
    // A note about an EARLIER switch that did not take says nothing
    // about this request. The page answers a tap from the note
    // (vpnStatus.last_switch), so it must be gone before this start
    // can block in its connection check; every failure path below
    // writes its own.
    host.note(null)

    // 1. The protect callback, BEFORE the engine has any chance to open
    //    an upstream socket.
    val protectRc = host.registerProtect()

    // 2. Ask before touching anything. A route the engine would refuse
    //    (cooling down, revoked, expired, needs a new file) is not worth
    //    a TUN on a first connect and must not cost a working route on a
    //    switch. The engine records the refusal in its diagnostics
    //    exactly as a refused setRoute does, so the page already knows
    //    why. No pre-check available (null) = attempt and read the
    //    outcome afterwards; step 5 is correct on its own.
    val pre = host.precheck(routeId)
    host.log(
      "route=$routeId register_protect_rc=$protectRc " +
        "precheck_refused=${pre?.refusedCode?.ifEmpty { "no" } ?: "n/a"}",
    )
    if (pre != null && pre.refusedCode.isNotEmpty()) {
      return settleFailure(routeId, pre, "refused by pre-check")
    }

    // 3. The TUN. Built once per connection, not once per route:
    //    building one replaces the interface the connected route is
    //    using.
    if (!host.tunHeld()) {
      val ended = host.establishTun()
      if (ended != null) return ended
    } else {
      host.log("route=$routeId reusing the TUN held (switch from ${host.lastGood() ?: "-"})")
      // The engine's own fetches ride the route that is about to be
      // replaced: retract their dialer while its listener is still
      // alive. Every path below that ends with a route up hands it back
      // (routeIsUp). Until then they fail closed, never direct.
      host.retractRefresh()
    }

    // 4. Activate the route. Blocks until the engine has proved it or
    //    given up; a stop or a newer start makes it return promptly.
    val routeRc = host.setRoute(routeId)
    host.log("route=$routeId set_route_rc=$routeRc")
    if (routeRc == 0) {
      // The engine is carrying this route now, whoever asked last.
      host.setLastGood(routeId)
      val up = host.routeIsUp(routeId)
      if (up == Outcome.UP) host.note(null)
      return up
    }
    if (host.superseded()) {
      host.log("route=$routeId superseded during its connection check; leaving the rest to the newer request")
      return Outcome.SUPERSEDED
    }

    // 5. It did not come up, and nobody asked for anything else.
    return settleFailure(routeId, host.engineView(), "set_route_rc=$routeRc")
  }

  /**
   * Connect with no route named: the engine chooses.
   *
   *   protect callback → (only when no TUN is held) build one →
   *   connectAuto() → publish the route the engine ended on.
   *
   * No pre-check: there is no single route to ask about, and the
   * engine leaves out the routes it would refuse by itself.
   *
   * When nothing connects ([SwitchPolicy.afterFailedAuto]): a route
   * that was connected before the call and still is, is kept;
   * otherwise everything is released and the engine's verdict is left
   * in the note for vpnStatus — except on a [reconnect], which keeps
   * the TUN ([Outcome.HOLDING]).
   *
   * @param reconnect the service is asking again by itself, after the
   *   engine ran out of routes while the person was connected. False
   *   when a person (or the system, for always-on VPN) asked.
   */
  fun runAuto(reconnect: Boolean = false): Outcome {
    host.log(
      "begin auto reconnect=$reconnect tun_held=${host.tunHeld()} last_good=${host.lastGood() ?: "-"}",
    )
    if (host.superseded()) {
      host.log("auto superseded before it began")
      return Outcome.SUPERSEDED
    }
    // As in run(): a note about an earlier request says nothing about
    // this one. A reconnect is not a new request — its note is the
    // reason the person is not connected, and stays until a route is up
    // or this attempt writes its own.
    if (!reconnect) host.note(null)

    val protectRc = host.registerProtect()

    // An engine that cannot be asked cannot choose a route. Found out
    // BEFORE a TUN is built: this is also the path a start by the
    // system takes (always-on VPN, a restart after the process was
    // killed), where the engine may not be loaded at all, and a TUN
    // nobody reads from would only cut the phone off.
    val before = host.engineView()
    host.log("auto register_protect_rc=$protectRc engine=${if (before == null) "unavailable" else "ok"}")
    if (before == null && !host.tunHeld()) {
      host.teardown("auto: the engine cannot be asked; nothing was built")
      return Outcome.DOWN
    }

    if (!host.tunHeld()) {
      val ended = host.establishTun()
      if (ended != null) return ended
    } else {
      // Unlike a switch, the engine's own fetches are left where they
      // are: when a route is connected the engine answers "already
      // connected" and replaces nothing.
      host.log("auto reusing the TUN held (on ${host.lastGood() ?: "-"})")
    }

    val res = host.connectAuto()
    host.log(
      if (res == null) {
        "auto: no answer from the engine"
      } else {
        "auto connected=${res.connected} route=${res.routeId.ifEmpty { "-" }} " +
          "verdict=${res.verdict.ifEmpty { "-" }} tried=${res.tried} candidates=${res.candidates}"
      },
    )
    if (res != null && res.connected && res.routeId.isNotEmpty()) {
      // The engine is carrying this route now, whoever asked last.
      host.setLastGood(res.routeId)
      val up = host.routeIsUp(res.routeId)
      if (up == Outcome.UP) host.note(null)
      return up
    }
    if (host.superseded()) {
      host.log("auto superseded while the engine was trying routes; leaving the rest to the newer request")
      return Outcome.SUPERSEDED
    }

    val verdict = when {
      res == null -> SwitchPolicy.VERDICT_UNAVAILABLE
      // An answer with no verdict: only the general one can be said.
      res.verdict.isEmpty() -> "all_failed"
      else -> res.verdict
    }
    val engine = host.engineView()
    val lastGood = host.lastGood()
    val decision = SwitchPolicy.afterFailedAuto(lastGood, engine)
    host.log(
      "auto found no route (verdict=$verdict): " +
        "engine_active=${engine?.activeRoute ?: "unknown"} running=${engine?.routeRunning ?: "unknown"} " +
        "last_good=${lastGood ?: "-"} decision=${decision.javaClass.simpleName}",
    )
    when (decision) {
      is SwitchPolicy.AfterFailure.Keep -> {
        host.note(SwitchPolicy.describeAutoFailure(decision.routeId, verdict))
        host.log("staying on route=${decision.routeId}; the engine still carries it")
        host.setLastGood(decision.routeId)
        return host.routeIsUp(decision.routeId)
      }
      is SwitchPolicy.AfterFailure.Restore -> {
        host.note(SwitchPolicy.describeAutoFailure(decision.routeId, verdict))
        val backRc = host.setRoute(decision.routeId)
        host.log("auto: going back to route=${decision.routeId} set_route_rc=$backRc")
        if (backRc == 0) {
          host.setLastGood(decision.routeId)
          return host.routeIsUp(decision.routeId)
        }
        if (host.superseded()) {
          host.log("superseded while going back to route=${decision.routeId}")
          return Outcome.SUPERSEDED
        }
      }
      SwitchPolicy.AfterFailure.TearDown -> {}
    }
    // Nothing is connected. The verdict is what the person is told.
    host.note(SwitchPolicy.describeAutoFailure(null, verdict))
    if (reconnect && res != null) {
      host.hold(verdict)
      host.log("auto: still no route; keeping the TUN closed and trying again later")
      return Outcome.HOLDING
    }
    host.teardown("auto found no route that carries (verdict=$verdict)")
    return Outcome.DOWN
  }

  /**
   * The route asked for did not come up and this start is still the
   * newest request: stay on the route that was connected if the engine
   * still carries it, go back to it if it does not, and only when there
   * is nothing to go back to, disconnect.
   *
   * The engine's verdict about the route that failed (connect_refused,
   * or route_check failed + its category) is left in its diagnostics
   * for the page in every case but one: a reconnect of the old route
   * overwrites it. The note keeps a copy for vpnStatus.
   */
  private fun settleFailure(routeId: String, engine: SwitchPolicy.EngineView?, what: String): Outcome {
    val lastGood = host.lastGood()
    val decision = SwitchPolicy.afterFailedStart(routeId, lastGood, engine)
    host.log(
      "route=$routeId did not come up ($what): " +
        "engine_active=${engine?.activeRoute ?: "unknown"} running=${engine?.routeRunning ?: "unknown"} " +
        "refused=${engine?.refusedCode?.ifEmpty { "-" } ?: "unknown"} " +
        "category=${engine?.failedCategory?.ifEmpty { "-" } ?: "unknown"} " +
        "last_good=${lastGood ?: "-"} decision=${decision.javaClass.simpleName}",
    )
    when (decision) {
      is SwitchPolicy.AfterFailure.Keep -> {
        host.note(SwitchPolicy.describeFailure(routeId, decision.routeId, engine))
        host.log("staying on route=${decision.routeId}; it was never interrupted")
        return host.routeIsUp(decision.routeId)
      }
      is SwitchPolicy.AfterFailure.Restore -> {
        host.note(SwitchPolicy.describeFailure(routeId, decision.routeId, engine))
        val backRc = host.setRoute(decision.routeId)
        host.log("going back to route=${decision.routeId} set_route_rc=$backRc")
        if (backRc == 0) {
          host.setLastGood(decision.routeId)
          return host.routeIsUp(decision.routeId)
        }
        if (host.superseded()) {
          host.log("superseded while going back to route=${decision.routeId}")
          return Outcome.SUPERSEDED
        }
        host.log("could not go back to route=${decision.routeId}; disconnecting")
        host.note(SwitchPolicy.describeFailure(routeId, null, engine))
        host.teardown("neither route=$routeId nor route=${decision.routeId} came up")
        return Outcome.DOWN
      }
      SwitchPolicy.AfterFailure.TearDown -> {
        // A first connect that failed is not a switch: the engine's
        // diagnostics already say everything there is to say about it.
        host.note(if (lastGood.isNullOrEmpty()) null else SwitchPolicy.describeFailure(routeId, null, engine))
        // The teardown's clearRoute does not cost the page the reason
        // for this failure: when the engine has already torn the route
        // down (the check failed) or never started it (refused), it
        // finds nothing running and leaves `route_check` /
        // `connect_refused` in the diagnostics as they are — the page
        // has not polled them yet (vpn_start resolved long ago), and
        // they are the only way it learns why.
        host.teardown("route=$routeId did not come up and there is no route to keep")
        return Outcome.DOWN
      }
    }
  }
}
