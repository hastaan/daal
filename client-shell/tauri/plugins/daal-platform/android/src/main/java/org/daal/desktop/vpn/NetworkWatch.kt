package org.daal.desktop.vpn

import java.security.MessageDigest

/**
 * What DaalVpnService tells the engine about the phone's network, and
 * when — with everything Android taken out, so it runs on a plain JVM
 * (src/test/.../NetworkWatchTest.kt).
 *
 * WHY. The engine cannot see the phone's network. Until this existed it
 * was told about a change only by the page (so never in the background),
 * with "wifi" or "mobile" as the whole identity, and it could not tell
 * "this phone has no internet" from "the server is dead". Android knows
 * all of that without any traffic of ours: which network is the default
 * one, whether the system has seen it reach the internet (VALIDATED),
 * whether it is metered. The service listens
 * (ConnectivityManager.NetworkCallback, registered while a connection
 * is wanted) and feeds every event in here; this class decides what is
 * worth one engine call.
 *
 * FOUR FACTS go to the engine (`DaalCoreBridge.networkFacts`):
 *
 *  - kind: wifi | cellular | ethernet | other | none. ("vpn" is in the
 *    engine's list and is never sent from here: an event about a VPN
 *    network — ours — is dropped, the service reports the network
 *    UNDER the tunnel.)
 *  - id: an opaque string that is the same every time the phone is on
 *    the same network, see [networkId]. Never logged, never stored on
 *    this side; the engine hashes it again before it keeps anything.
 *  - validated: 1 the system reached the internet through it, 0 it did
 *    not, -1 not known.
 *  - metered: 1 / 0 / -1.
 *
 * WHEN. Android reports a network in pieces (available, then its
 * capabilities, then its addresses) and repeats itself often (a
 * capabilities event for every change of signal strength). So:
 *
 *  - identical facts are sent once;
 *  - the first facts after [start] go at once — the engine is about to
 *    connect and should know where it is;
 *  - a later change waits [SETTLE_MS] for the pieces to settle, a lost
 *    network [NONE_SETTLE_MS] (a move from wifi to mobile data passes
 *    through "no network" for a moment, and a blip that comes back as
 *    the same network is not a change at all);
 *  - a network that keeps changing is still reported, [MAX_WAIT_MS]
 *    after the first unsent change at the latest;
 *  - a network Android announced but never described is reported as
 *    kind "other", nothing known, after [DESCRIBE_WAIT_MS].
 *
 * Every method takes the caller's clock (milliseconds, monotonic) and
 * returns how long from now the caller should call [due], or null when
 * there is nothing to wait for. Thread-safe: callbacks arrive on
 * Android's connectivity thread, the timer on another.
 */
class NetworkWatch {

  /** What one engine call carries. */
  data class Facts(val kind: String, val id: String, val validated: Int, val metered: Int)

  /** The part of Android's NetworkCapabilities that is read. */
  data class Caps(
    val wifi: Boolean = false,
    val cellular: Boolean = false,
    val ethernet: Boolean = false,
    /** The network is a VPN (ours): not what is reported. */
    val vpn: Boolean = false,
    val validated: Boolean = false,
    val notMetered: Boolean = false,
    /** SIM operator code (digits) on a cellular network, else "". */
    val operator: String = "",
  )

  /** The part of Android's LinkProperties that is read. */
  data class Link(
    /** IPv4 networks the phone has an address in, as [subnet] writes them. */
    val v4Subnets: List<String> = emptyList(),
    /** Default IPv4 gateway, textual; "" when none. */
    val v4Gateway: String = "",
    /** Default IPv6 gateway, textual; "" when none. */
    val v6Gateway: String = "",
  )

  private class Seen(val handle: Long, val since: Long) {
    var caps: Caps? = null
    var link: Link? = null
  }

  private var running = false
  private var seen: Seen? = null

  /**
   * The network [seen] replaced when Android named another one, kept
   * until that other one has said what it is: if it turns out to be a
   * VPN, this is still the network to describe.
   */
  private var displaced: Seen? = null

  /** Handles whose capabilities said VPN: nothing about them is used. */
  private val vpnHandles = HashSet<Long>()

  /** The facts the engine has (the last ones handed out by [due]). */
  private var sent: Facts? = null

  /** What [sent] was before that, to go back to if the call failed. */
  private var sentBefore: Facts? = null

  /** Facts waiting to be sent, and the clock time they may go at. */
  private var pending: Facts? = null
  private var dueAt = 0L

  /** When the oldest change that has not been sent was first seen. */
  private var firstChangeAt = -1L
  private var retries = 0

  /** Facts the engine call kept failing for; not offered again as they are. */
  private var gaveUp: Facts? = null

  /**
   * The service starts listening. [hasNetwork]: Android names a default
   * network right now (its description follows in the callbacks). With
   * none, "no network" is the first fact, sent at once — Android calls
   * nothing back when there is no network to describe.
   */
  @Synchronized
  fun start(hasNetwork: Boolean, nowMs: Long): Long? {
    reset()
    running = true
    seen = if (hasNetwork) Seen(HANDLE_UNDESCRIBED, nowMs) else null
    return evaluate(nowMs)
  }

  /**
   * The service starts listening and ALREADY KNOWS the default network:
   * it asked Android for its description before registering the
   * callback. Returns the first facts, to be delivered to the engine
   * BEFORE the connect is started — or null when what Android gave
   * does not describe a network to report (no capabilities, a VPN, no
   * addresses yet); the watch is then started exactly as [start] with
   * a network would, and the callbacks describe it.
   *
   * WHY. The callbacks reach the engine by way of two other threads,
   * and nothing ordered them before the connect. On the first press in
   * a process the engine could start searching while it still believed
   * it was on no particular network: the route that carried on this
   * Wi-Fi yesterday was not tried first and alone, and two routes were
   * opened together on what should have been the quiet, usual press.
   *
   * The facts returned count as sent; report the call with [delivered].
   */
  @Synchronized
  fun startDescribed(handle: Long, caps: Caps?, link: Link?, nowMs: Long): Facts? {
    reset()
    running = true
    if (caps == null || caps.vpn || link == null) {
      seen = Seen(HANDLE_UNDESCRIBED, nowMs)
      evaluate(nowMs)
      return null
    }
    seen = Seen(handle, nowMs).also {
      it.caps = caps
      it.link = link
    }
    evaluate(nowMs)
    return due(nowMs)
  }

  /** The service stops listening: everything is forgotten. */
  @Synchronized
  fun stop() = reset()

  private fun reset() {
    running = false
    seen = null
    displaced = null
    vpnHandles.clear()
    sent = null
    sentBefore = null
    pending = null
    dueAt = 0L
    firstChangeAt = -1L
    retries = 0
    gaveUp = null
  }

  /** Android: [handle] is now the default network. */
  @Synchronized
  fun available(handle: Long, nowMs: Long): Long? {
    if (!running) return null
    if (handle in vpnHandles) return waitFrom(nowMs)
    val s = seen
    if (s?.handle != handle) {
      // Android names a network before it says what it is. Should this
      // one turn out to be a VPN ([capabilities]), the one it replaced
      // here is put back as it was.
      if (s != null && s.handle != HANDLE_UNDESCRIBED) displaced = s
      seen = Seen(handle, nowMs)
    }
    return evaluate(nowMs)
  }

  /**
   * Android: the capabilities of [handle]. A VPN's are dropped — and so
   * is everything else about that handle, before and after: the
   * [available] that announced it is undone, its [link] and its [lost]
   * are ignored. (Dropping the capabilities alone left the VPN's handle
   * as the network being described, with the real network's description
   * thrown away: two seconds later the engine was told "kind other, no
   * id" and filed what it learned under a network that does not exist.)
   */
  @Synchronized
  fun capabilities(handle: Long, caps: Caps, nowMs: Long): Long? {
    if (!running) return null
    if (caps.vpn) {
      if (vpnHandles.size >= MAX_VPN_HANDLES) vpnHandles.clear()
      vpnHandles.add(handle)
      if (seen?.handle == handle) {
        seen = displaced
        displaced = null
      }
      if (displaced?.handle == handle) displaced = null
      return evaluate(nowMs)
    }
    vpnHandles.remove(handle)
    val s = seenFor(handle, nowMs)
    s.caps = caps
    return evaluate(nowMs)
  }

  /** Android: the addresses and routes of [handle]. */
  @Synchronized
  fun link(handle: Long, link: Link, nowMs: Long): Long? {
    if (!running) return null
    if (handle in vpnHandles) return waitFrom(nowMs)
    val s = seenFor(handle, nowMs)
    s.link = link
    return evaluate(nowMs)
  }

  /**
   * Android: [handle] is gone. Only the loss of the network being
   * described means "no network": Android may report the old network
   * lost after it has already named the new one.
   */
  @Synchronized
  fun lost(handle: Long, nowMs: Long): Long? {
    if (!running) return null
    if (vpnHandles.remove(handle)) return waitFrom(nowMs)
    if (displaced?.handle == handle) displaced = null
    val s = seen
    if (s != null && (s.handle == handle || s.handle == HANDLE_UNDESCRIBED)) seen = null
    return evaluate(nowMs)
  }

  private fun seenFor(handle: Long, nowMs: Long): Seen {
    val s = seen
    if (s != null && s.handle == handle) return s
    return Seen(handle, nowMs).also { seen = it }
  }

  /**
   * The facts to send now, or null when nothing is due. The caller
   * makes the engine call and reports how it went with [delivered];
   * until then these count as what the engine has.
   */
  @Synchronized
  fun due(nowMs: Long): Facts? {
    if (!running) return null
    evaluate(nowMs)
    val p = pending ?: return null
    if (nowMs < dueAt) return null
    pending = null
    firstChangeAt = -1L
    sentBefore = sent
    sent = p
    return p
  }

  /** How long until [due] should be asked again; null = no need. */
  @Synchronized
  fun nextIn(nowMs: Long): Long? = if (running) evaluate(nowMs) else null

  /**
   * How the engine call for [facts] went. A failed call is repeated
   * after [RETRY_MS], [MAX_RETRIES] times at most (an engine that is
   * not loaded will not load by being asked again); a later change in
   * the network is tried regardless.
   */
  @Synchronized
  fun delivered(facts: Facts, ok: Boolean, nowMs: Long): Long? {
    if (!running || sent != facts) return waitFrom(nowMs)
    if (ok) {
      retries = 0
      return waitFrom(nowMs)
    }
    // The engine does not have them after all.
    sent = sentBefore
    if (pending == null && current(nowMs) == facts) {
      if (retries < MAX_RETRIES) {
        retries++
        pending = facts
        dueAt = nowMs + RETRY_MS
      } else {
        gaveUp = facts
      }
    }
    return waitFrom(nowMs)
  }

  /** What the events so far add up to; null = not describable yet. */
  private fun current(nowMs: Long): Facts? {
    val s = seen ?: return NONE
    val caps = s.caps
    val described = nowMs - s.since >= DESCRIBE_WAIT_MS
    if (caps == null) return if (described) Facts(KIND_OTHER, "", -1, -1) else null
    val link = s.link
    if (link == null && !described) return null
    val kind = kind(caps)
    return Facts(
      kind = kind,
      id = networkId(kind, caps.operator, link ?: Link()),
      validated = if (caps.validated) 1 else 0,
      metered = if (caps.notMetered) 0 else 1,
    )
  }

  private fun evaluate(nowMs: Long): Long? {
    val now = current(nowMs)
    if (now == null) {
      // There is a network and Android has not described it yet. What
      // was pending is no longer true (a "no network" in the middle of
      // a move, say) and is not sent; the clock for [MAX_WAIT_MS]
      // keeps running from the first change.
      if (pending != null && firstChangeAt < 0) firstChangeAt = nowMs
      pending = null
      val s = seen
      return if (s == null) 0L else (s.since + DESCRIBE_WAIT_MS - nowMs).coerceAtLeast(0L)
    }
    if (now == sent || now == gaveUp) {
      // Back where the engine thinks we are (or the call for exactly
      // this keeps failing): nothing to say.
      pending = null
      firstChangeAt = -1L
      return null
    }
    if (now != pending) {
      if (firstChangeAt < 0) firstChangeAt = nowMs
      retries = 0
      gaveUp = null
      pending = now
      dueAt = when {
        // Nothing sent yet: the engine should know before it connects.
        sent == null -> nowMs
        else -> minOf(nowMs + (if (now.kind == KIND_NONE) NONE_SETTLE_MS else SETTLE_MS), firstChangeAt + MAX_WAIT_MS)
      }
    }
    return waitFrom(nowMs)
  }

  private fun waitFrom(nowMs: Long): Long? =
    if (pending == null) null else (dueAt - nowMs).coerceAtLeast(0L)

  companion object {
    const val KIND_WIFI = "wifi"
    const val KIND_CELLULAR = "cellular"
    const val KIND_ETHERNET = "ethernet"
    const val KIND_OTHER = "other"
    const val KIND_NONE = "none"

    /** No network: the system knows there is no internet; metering is moot. */
    @JvmField val NONE = Facts(KIND_NONE, "", 0, -1)

    /** A later change waits this long for its pieces to arrive. */
    const val SETTLE_MS = 750L

    /** "No network" waits longer: most losses are the middle of a move. */
    const val NONE_SETTLE_MS = 2_000L

    /** A network that never stops changing is reported after this. */
    const val MAX_WAIT_MS = 5_000L

    /** How long Android has to describe a network it announced. */
    const val DESCRIBE_WAIT_MS = 2_000L

    const val RETRY_MS = 5_000L

    /** How many VPN handles are remembered (Android never reuses one). */
    private const val MAX_VPN_HANDLES = 16

    /**
     * How long a connect waits for the first facts to have reached the
     * engine (the call is made on another thread) before it starts
     * anyway. The call itself takes milliseconds.
     */
    const val FIRST_FACTS_WAIT_MS = 1_000L
    const val MAX_RETRIES = 3

    /**
     * While the service is holding (interface up, no route), a network
     * that has just appeared or been validated is a reason to search
     * again at once
     * instead of waiting out the backoff — at most once per this long,
     * so a network that flickers does not start a pass per flicker.
     */
    const val RETRY_ON_NETWORK_MIN_MS = 30_000L

    /** A default network Android named before the callbacks described it. */
    private const val HANDLE_UNDESCRIBED = Long.MIN_VALUE

    @JvmStatic
    fun kind(caps: Caps): String = when {
      caps.wifi -> KIND_WIFI
      caps.ethernet -> KIND_ETHERNET
      caps.cellular -> KIND_CELLULAR
      else -> KIND_OTHER
    }

    /**
     * The opaque per-network id: the same string whenever the phone is
     * on the same network again, without the location permission (so
     * no SSID and no BSSID — Android hides both without it).
     *
     * WHAT IT IS MADE OF, and how stable that is:
     *
     *  - wifi / ethernet / other: the IPv4 network(s) the phone has an
     *    address in (network address + prefix length, NOT the phone's
     *    own address, which a new lease changes) and the default IPv4
     *    gateway. The same router gives the same answer on every
     *    reconnect, for as long as nobody changes its LAN range. Two
     *    different networks that both use a router's factory range
     *    (192.168.1.0/24 behind 192.168.1.1 is common) get the SAME id
     *    and share one memory: less precise, never wrong about more
     *    than "which of those". On a network with no IPv4 at all, the
     *    default IPv6 gateway (usually a link-local address fixed by
     *    the router's hardware). IPv6 is deliberately not mixed in when
     *    IPv4 exists: it arrives seconds later and would change the id
     *    of a network while the phone is joining it. The interface name
     *    is not used (always "wlan0"), nor Android's network handle (a
     *    new number on every reconnect).
     *  - cellular: the SIM operator's code, so one id per operator —
     *    the same on every tower and after every reconnect, and it
     *    separates two SIMs. Addresses are not used: a mobile network
     *    hands out a different one every time. With no SIM operator
     *    readable the id is empty and the kind alone is the identity.
     *
     * What is returned is a digest of those values, so that no address
     * crosses to the engine or can end up in a log by accident. It is
     * NOT a secret (the inputs are guessable); the engine hashes it
     * again with its own network hash. "" = nothing to tell networks of
     * this kind apart with.
     */
    @JvmStatic
    fun networkId(kind: String, operator: String, link: Link): String {
      val raw = when (kind) {
        KIND_NONE -> ""
        KIND_CELLULAR -> {
          val op = operator.filter { it in '0'..'9' }
          if (op.isEmpty()) "" else "op|$op"
        }
        else -> {
          val nets = link.v4Subnets.filter { it.isNotEmpty() }.distinct().sorted()
          val gw4 = bare(link.v4Gateway)
          val gw6 = bare(link.v6Gateway)
          when {
            nets.isNotEmpty() -> "v4|" + nets.joinToString(",") + "|" + gw4
            gw4.isNotEmpty() -> "v4||$gw4"
            gw6.isNotEmpty() -> "v6|$gw6"
            else -> ""
          }
        }
      }
      if (raw.isEmpty()) return ""
      val digest = MessageDigest.getInstance("SHA-256").digest("daal-network-v1|$kind|$raw".toByteArray(Charsets.UTF_8))
      val hex = StringBuilder(32)
      for (i in 0 until 16) {
        val b = digest[i].toInt() and 0xff
        hex.append(HEX[b ushr 4]).append(HEX[b and 0x0f])
      }
      return hex.toString()
    }

    private const val HEX = "0123456789abcdef"

    /** An address as text, without a zone ("fe80::1%wlan0") or a leading "/". */
    private fun bare(address: String): String =
      address.trim().substringBefore('%').substringAfterLast('/').lowercase()

    /**
     * The IPv4 network an address is in: "192.168.1.0/24" for
     * 192.168.1.37 with prefix 24. "" for anything that is not four
     * bytes and a prefix of 0–32.
     */
    @JvmStatic
    fun subnet(address: ByteArray, prefixLength: Int): String {
      if (address.size != 4 || prefixLength < 0 || prefixLength > 32) return ""
      var v = 0L
      for (b in address) v = (v shl 8) or (b.toLong() and 0xff)
      val mask = if (prefixLength == 0) 0L else (0xffffffffL shl (32 - prefixLength)) and 0xffffffffL
      val n = v and mask
      return "${(n ushr 24) and 0xff}.${(n ushr 16) and 0xff}.${(n ushr 8) and 0xff}.${n and 0xff}/$prefixLength"
    }

    /**
     * Should the service ask the engine to search again NOW, because of
     * the facts just delivered? Only while holding, only when there is
     * a network, and only when that is news: there was none before, it
     * is a different network, or the system has just seen it reach the
     * internet.
     *
     * A network the system has NOT validated still counts when it is
     * new: on a filtered network Android's own check may never pass
     * while a route carries all the same, and a search in which nothing
     * answers costs the engine nothing it keeps.
     *
     * @param before          the facts delivered before these, or null
     * @param sinceLastRetryMs time since the last retry started this way
     */
    @JvmStatic
    fun retryNow(holding: Boolean, before: Facts?, now: Facts, sinceLastRetryMs: Long): Boolean {
      if (!holding || now.kind == KIND_NONE) return false
      if (sinceLastRetryMs < RETRY_ON_NETWORK_MIN_MS) return false
      if (before == null || before.kind != now.kind || before.id != now.id) return true
      return before.validated != 1 && now.validated == 1
    }

    /**
     * The host knows the phone has no network at all. (Not "the system
     * could not validate it": on a filtered network Android's own check
     * can fail while a route still carries, so that alone never puts
     * "no internet" in front of the person.)
     */
    @JvmStatic
    fun noNetwork(facts: Facts?): Boolean = facts != null && facts.kind == KIND_NONE
  }
}

/**
 * Which DNS servers the engine should hold (`engine_set_link_resolvers`)
 * when TWO reporters in this process watch the network: the app itself
 * (LinkResolvers' app-scope callback, from the moment the page loads,
 * with or without a connection) and DaalVpnService (while it runs).
 * Pure, so it runs on a plain JVM (src/test/.../ResolverGateTest.kt).
 *
 * Both watch the same thing, the best network that has internet and is
 * NOT a VPN, so in the usual case they say the same list twice, and
 * the second time nothing is sent. They disagree only in timing: one
 * hears "network B is here" before the other hears "network A is
 * gone". THE RULE:
 *
 *  - Each network is remembered by its handle with the servers last
 *    said for it. The network that spoke last is the current one; its
 *    list is what the engine should hold.
 *  - "Lost" forgets that network for both reporters (Android does not
 *    lose a network for one callback and keep it for another with the
 *    same request). The engine is then told the list of the network
 *    that spoke last among those still known, and the empty list only
 *    when none is left. So a "lost" for a network that is not the
 *    current one (the old Wi-Fi, after mobile data already spoke)
 *    changes nothing, and can never wipe a good list just set.
 *  - A reporter that stops listening ([detach]) sends nothing: the
 *    networks only it knew are forgotten, the engine keeps its list
 *    (the other reporter, if listening, knows the same networks).
 *  - The same list is sent once. A send the engine did not take
 *    (library not loaded yet, call threw) is not counted as sent, so
 *    the next event, or [pending], sends it again.
 *
 * Every method returns the list to send now, or null for nothing.
 * Thread-safe; the caller still makes its sends one at a time, in the
 * order they were answered, and reports each with [delivered].
 */
class ResolverGate {
  private class Net(var servers: List<String>, var seq: Long, val by: MutableSet<String>)

  private val nets = HashMap<Long, Net>()
  private var seq = 0L

  /** True once any reporter has said anything: from then on "none known" means []. */
  private var spoke = false

  /** What the engine last accepted; null when nothing yet, or the last send failed. */
  private var sent: List<String>? = null

  /**
   * The network [reporter] is on has these servers (its link properties).
   *
   * [single]: the reporter follows ONE network at a time (Android 12+'s
   * registerBestMatchingNetworkCallback, like the default-network
   * callback, calls onLost only when no replacement exists: after
   * Wi-Fi -> mobile data no "lost" ever comes for the Wi-Fi). Speaking
   * for this network then means the reporter has left every other one:
   * it is taken off them, and a network no reporter is on any more is
   * forgotten, so a later "lost" of this one leaves nothing stale to fall
   * back to. False for the pre-12 plain listener, which hears every
   * matching network and a "lost" for each.
   */
  @Synchronized
  fun link(reporter: String, handle: Long, servers: List<String>, single: Boolean = false): List<String>? {
    spoke = true
    if (single) {
      val it = nets.entries.iterator()
      while (it.hasNext()) {
        val e = it.next()
        if (e.key == handle) continue
        e.value.by.remove(reporter)
        if (e.value.by.isEmpty()) it.remove()
      }
    }
    val n = nets.getOrPut(handle) { Net(servers, 0L, HashSet()) }
    n.servers = servers
    n.seq = ++seq
    n.by.add(reporter)
    return toSend()
  }

  /** [reporter] heard that network [handle] is gone. */
  @Synchronized
  fun lost(@Suppress("UNUSED_PARAMETER") reporter: String, handle: Long): List<String>? {
    spoke = true
    nets.remove(handle)
    return toSend()
  }

  /** [reporter] stopped listening. Never sends. */
  @Synchronized
  fun detach(reporter: String) {
    val it = nets.values.iterator()
    while (it.hasNext()) {
      val n = it.next()
      n.by.remove(reporter)
      if (n.by.isEmpty()) it.remove()
    }
    // Nobody listening: nothing is known, which is not "no network".
    // The engine keeps what it holds until someone speaks again.
    if (nets.isEmpty()) spoke = false
  }

  /** The engine's answer to a send of [servers]: taken (rc >= 0) or not. */
  @Synchronized
  fun delivered(servers: List<String>, ok: Boolean) {
    sent = if (ok) servers else null
  }

  /** What should be sent again, if the engine does not hold it yet; null when it does. */
  @Synchronized
  fun pending(): List<String>? = toSend()

  /** The list the engine should hold now; null before anyone has spoken. */
  @Synchronized
  fun wanted(): List<String>? {
    if (!spoke) return null
    return nets.values.maxByOrNull { it.seq }?.servers ?: emptyList()
  }

  private fun toSend(): List<String>? {
    val want = wanted() ?: return null
    return if (want == sent) null else want
  }
}
