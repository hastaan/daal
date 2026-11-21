#!/usr/bin/env bash
# e2e — the whole worldbox matrix from one command: every family, every
# censor scenario, every publisher-side operation, one report, one exit
# status. `./daal e2e` calls this.
#
#   ./e2e.sh                 quick: ~1 minute. What the pre-push hook runs.
#   ./e2e.sh full            everything: ~5 minutes.
#   ./e2e.sh full -j 4       worlds at a time (default: half the cores, at most 8)
#   ./e2e.sh --plan full     print the worlds a mode runs, and stop
#   ./e2e.sh quick --only clean,sni-rst      just these worlds of the plan
#
# quick   no censor × all 7 families (tree daemon) with a live route switch
#         (TCP family ↔ QUIC family), revoke, L1 rotation, mgmt-auth and
#         tamper; the automatic connect (the one button: pick, try two at
#         a time, move on, remember, measure, explain, fall over) on a
#         default relay's four routes; the pinned RELEASE artefacts × the default
#         families; and every censor scenario × one TCP and one QUIC family.
# full    every censor scenario × all 7 families; the whole lifecycle
#         (recipients, revoke, L1, L2, L3, freshness, mgmt-auth, capability
#         honesty, tamper, wrong credentials, repeated relay restarts) on the
#         tree daemon and again (bar the restarts) on
#         the pinned release artefacts; rotation under a censor; a live
#         route switch between every ordered pair of families; the
#         automatic connect on all 7 families' routes and under the
#         scenarios where nothing, or only QUIC, is stopped, and what it
#         does on its own clock (grade a slow route, move for speed and
#         hold, per-network memory, network_down on the host's word); and the
#         pinned artefacts × all 7 families (FINDINGS F-002, kept visible);
#         and a relay provisioned with two opt-in families only (FAM-4);
#         and the add-on worlds below.
# addons  the publisher add-ons (docs/optional-addons-plan.md): standby
#         address (rent, sign sealed, switch under a connected phone, no
#         key → no dial, typed key, open variant, stale address), the CDN
#         front (provisioning against the lab's Cloudflare, every cdn-*
#         censor) and the Google channel (Path A/B, every refresh-google-*
#         censor) on the tree daemon; then the standby ops and one cdn-*
#         world again on the PINNED release box (standby.pinned,
#         cdn-sni-block-ech.pinned). Parts that wait on engine code still landing report
#         SKIPPED "WAITS ON <lane> <item>" (driver/addons_net.go).
#
# Each world is one ./run.sh (own namespaces, own evidence directory under
# out/). A world is rootless and hermetic; several run side by side.
#
# Exit status:
#    0  every world ran and nothing is red that an open finding
#       (known-findings.json → FINDINGS.md) does not explain
#    1  an unexpected red check, or a known finding that did not reproduce
#    2  a world did not run (run.sh died, or recorded nothing to judge):
#       the rig is broken, not Daal. A world stopped early by a red check
#       of its own is NOT this: it is judged, and exits 1
#   77  SKIPPED — this machine cannot host the rig. Not a pass.
set -uo pipefail
RIG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mode=quick; jobs=""; only=""; plan_only=""
while (($#)); do
  case "$1" in
    quick|full|addons) mode="$1" ;;
    -j) jobs="$2"; shift ;;
    --only) only="$2"; shift ;;
    --plan) plan_only=1 ;;
    -h|--help) sed -n '2,41p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "e2e: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
if [[ -z "$jobs" ]]; then
  jobs=$(( $(nproc) / 2 )); (( jobs > 8 )) && jobs=8; (( jobs < 1 )) && jobs=1
fi

# ---- the plan: label <TAB> run.sh arguments ------------------------------
# The longest worlds first, so the short ones fill in around them.
# The add-on scenarios (cdn-*, refresh-google-*) are about the CDN route
# and the Google channel, which only their ops exercise: they are not in
# the generic loop below but in the add-on worlds (addons, and full).
scenarios=(); addon_scenarios=()
for f in "$RIG"/scenarios/*.json; do
  s="$(basename "$f" .json)"
  case "$s" in clean) ;; cdn-*|refresh-google-*) addon_scenarios+=("$s") ;; *) scenarios+=("$s") ;; esac
done
addon_worlds() { # [family…] for the scenario worlds; none = every family (full)
  local fams="$*"
  plan+=("standby"$'\t'"--mgmt=tree --ops standby,standby-promote,standby-sealed,standby-open,standby-stale clean vless-reality hysteria2")   # add-on 1: rent, sign sealed, switch under a connected phone (freshness), no key → no dial, typed key, open-mode variant, stale address to a stranger
  plan+=("standby-google"$'\t'"--mgmt=tree --ops standby-google clean vless-reality")   # add-on 1 + 3: the switch and the key through the Google channel with the ordinary mirrors cut
  plan+=("cdn-provision"$'\t'"--mgmt=tree --ops cdn-provision clean vless-reality")   # add-on 2, publisher side: token verdicts, rollback, zone state, firewall, ECH config, posture, front test, removal
  plan+=("google-channel"$'\t'"--mgmt=tree --ops google-channel clean vless-reality")   # add-on 3, publisher side: Path A (API off, half-way failure, resume), update through the front, refusals, Path B
  for s in "${addon_scenarios[@]}"; do
    case "$s" in
      cdn-*) plan+=("$s"$'\t'"--mgmt=tree --ops cdn $s${fams:+ $fams}") ;;   # the CDN route under this censor (scenario's cdn.expect)
      refresh-google-*) plan+=("$s"$'\t'"--mgmt=tree --ops google-refresh $s${fams:+ $fams}") ;;   # the walk through the Google front under this censor (google_expect)
    esac
  done
  # The add-ons on the PINNED box (no --mgmt=tree: the box downloads the
  # release this tree pins from the lab mirror, as a real relay does). The
  # box side of both add-ons is the release's daal-relay-mgmt — the standby
  # bound with `scope link`, the door at POST /cdn — so the tree daemon
  # above cannot speak for what people's relays actually run.
  plan+=("standby.pinned"$'\t'"--ops standby,standby-promote,standby-sealed,standby-open,standby-stale clean vless-reality hysteria2")   # add-on 1 on the released relay
  plan+=("cdn-sni-block-ech.pinned"$'\t'"--ops cdn cdn-sni-block-ech${fams:+ $fams}")   # add-on 2 on the released relay: the door, the route through the edge with ECH, one censor
}
plan=()
if [[ "$mode" == addons ]]; then
  addon_worlds vless-reality hysteria2
elif [[ "$mode" == quick ]]; then
  plan+=("auto"$'\t'"--mgmt=tree --ops auto clean vless-reality hysteria2")   # the one button, on the four routes a default relay serves: ~70 s, the longest world of this mode, so it is its own and first
  plan+=("clean"$'\t'"--mgmt=tree --ops switch,revoke,l1,mgmtauth,tamper clean")   # switch first: it uses r1's pack as minted
  plan+=("release"$'\t'"--ops revoke,mgmtauth clean @default")
  for s in "${scenarios[@]}"; do plan+=("$s"$'\t'"--mgmt=tree $s vless-reality hysteria2"); done
else
  plan+=("release.lifecycle"$'\t'"--ops lifecycle,tamper,wrongcreds clean @default")
  plan+=("clean.rotation"$'\t'"--mgmt=tree --ops l1,l2,l3,freshness,caps clean")   # l2 THEN l3: the cover host moves, then the address (naive, FINDINGS LC-3); the other order runs under udp-blackhole and in release.lifecycle
  plan+=("clean.recipients"$'\t'"--mgmt=tree --ops recipients,revoke,wrongcreds,tamper,mgmtauth,restarts clean")
  plan+=("clean.switch"$'\t'"--mgmt=tree --ops switch,switch-all clean")   # one phone, many routes: every ordered pair of families (FINDINGS SW-0, SW-1, SW-2)
  plan+=("clean.auto"$'\t'"--mgmt=tree --ops auto clean")   # the one button: pick, try, move on, remember, explain, fall over
  plan+=("blocked-while-connected"$'\t'"--mgmt=tree --ops blocked-while-connected clean vless-reality hysteria2")   # blackout plan C0: the relay's address is null-routed UNDER a connected phone; the engine finds the publisher's new address by itself (one direct walk with the instance stopped) and reconnects; a phone that cannot see the mirrors says so
  plan+=("auto-deep"$'\t'"--mgmt=tree --ops auto-deep clean vless-reality hysteria2")   # …and what it does on its own clock or at the cost of a whole failed pass: grade a slow route, move off one for speed and hold, stay put on a metered network, keep each network's memory apart, say network_down when the host says so, leave nothing of a side instance behind
  for s in "${scenarios[@]}"; do
    if [[ "$s" == udp-blackhole ]]; then
      plan+=("$s"$'\t'"--mgmt=tree --ops recipients,l1,l3,l2,caps $s")   # rotation under a censor
    elif [[ "$s" == relay-ip-block || "$s" == total-blackout || "$s" == quic-drop ]]; then
      plan+=("$s"$'\t'"--mgmt=tree --ops auto $s")   # the one button where nothing can carry (and the verdict it must give), and where only the QUIC routes are stopped
    elif [[ "$s" == sni-rst-stateless || "$s" == sni-rst-first-two ]]; then
      plan+=("$s"$'\t'"--mgmt=tree --ops desync $s")   # the engine's own ClientHello split (core/desync) against a box that reads one / two packets: which presets slip through, and that the split is on the wire
    else
      plan+=("$s"$'\t'"--mgmt=tree $s")
    fi
  done
  addon_worlds
  plan+=("release.all-families"$'\t'"clean")
  plan+=("narrow-relay"$'\t'"--mgmt=tree --relay-families=shadowsocks,anytls clean shadowsocks anytls")   # FINDINGS FAM-4
fi
if [[ -n "$only" ]]; then
  kept=()
  for p in "${plan[@]}"; do [[ ",$only," == *",${p%%$'\t'*},"* ]] && kept+=("$p"); done
  plan=("${kept[@]}")
  (( ${#plan[@]} )) || { echo "e2e: --only $only matches no world of the $mode plan (see --plan)" >&2; exit 2; }
fi
if [[ -n "$plan_only" ]]; then printf '%s\n' "${plan[@]}"; exit 0; fi

# ---- can this machine host it at all? ------------------------------------
"$RIG/run.sh" --preflight >/dev/null || exit $?

# ---- one build, shared by every world ------------------------------------
# Under a lock: a second e2e.sh (the pre-push hook, while somebody is
# running the full matrix) must not relink a directory mid-build. Running
# worlds are not disturbed by a rebuild: every file is replaced by rename.
export WB_BIN="${WB_BIN:-$RIG/out/.e2e-bin}"
mkdir -p "$WB_BIN"
t_start=$(date +%s)
flock "$WB_BIN/.lock" "$RIG/run.sh" --mgmt=tree --build-only >&2 || { echo "e2e: build failed" >&2; exit 2; }
export WB_NO_BUILD=1
# Worlds run side by side: keep enough evidence directories that none is
# pruned while this matrix is still being read.
export WB_KEEP_RUNS="${WB_KEEP_RUNS:-60}"

# Reports are pruned per kind, never across kinds: the quick matrix runs on
# every push, and must not evict the last full report (the only evidence for
# the families and rungs quick does not reach). A --only run is a partial
# matrix and is its own kind, so it cannot evict a whole one either.
kind="$mode"; [[ -n "$only" ]] && kind="$mode-only"
out="$RIG/out/e2e/$(date +%Y%m%d-%H%M%S)-$kind-$$"
mkdir -p "$out"
prune_reports() { # kind keep
  ls -1dt "$RIG"/out/e2e/2*-"$1"-[0-9]* 2>/dev/null | tail -n +$(( $2 + 1 )) | xargs -r rm -rf
}
prune_reports quick 8
prune_reports full 4
prune_reports quick-only 4
prune_reports full-only 4
prune_reports addons 4
prune_reports addons-only 4
printf '%s\n' "${plan[@]}" >"$out/plan.tsv"

# A world that hangs must not hang a push: the driver gives itself 15
# minutes, and this is the belt to that pair of braces. Killing run.sh
# kills the world (the driver is PID 1 of its pid namespace).
cap=1200
run_one() { # label args…
  local label="$1"; shift
  local t0; t0=$(date +%s)
  # shellcheck disable=SC2086
  timeout -k 10 "$cap" "$RIG/run.sh" --json "$@" >"$out/$label.jsonl" 2>"$out/$label.log"
  local rc=$?
  echo "$rc" >"$out/$label.rc"; echo $(( $(date +%s) - t0 )) >"$out/$label.secs"
  printf '  %-24s exit %s  %3ss\n' "$label" "$rc" "$(cat "$out/$label.secs")" >&2
}
echo "e2e: $mode — ${#plan[@]} worlds, $jobs at a time; per-world logs in $out" >&2
# Interrupted: take every world down with us. Each job is a subshell whose
# child is `timeout`; TERM to that reaches run.sh (by then `unshare`), and
# when it dies the kernel kills the world's PID 1 and everything in it.
stop_worlds() {
  local p
  for p in $(jobs -rp); do pkill -TERM -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; done
  wait
  echo "e2e: interrupted — every world was torn down" >&2
  exit 130
}
trap stop_worlds INT TERM
for p in "${plan[@]}"; do
  while (( $(jobs -rp | wc -l) >= jobs )); do wait -n; done
  # shellcheck disable=SC2086
  run_one "${p%%$'\t'*}" ${p#*$'\t'} &
done
wait
trap - INT TERM

"$WB_BIN/wb" summary --rig "$RIG" --dir "$out" --mode "$mode" --title "worldbox e2e ($mode)" | tee "$out/report.txt"
rc=${PIPESTATUS[0]}
# A gate that runs this (pre-push) repeats the race counts in its own
# one-line result: "passed" with a race at its budget is not "passed at 0".
if [[ -n "${WB_INTERMITTENT_FILE:-}" ]]; then
  grep -m1 '^INTERMITTENT' "$out/report.txt" >"$WB_INTERMITTENT_FILE" 2>/dev/null || :
fi
echo "elapsed: $(( $(date +%s) - t_start ))s   report: $out/report.txt   evidence per world: $RIG/out/<run>/ (path at the top of each $out/<world>.log)"
exit "$rc"
