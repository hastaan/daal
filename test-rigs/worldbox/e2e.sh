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
# quick   no censor × all 7 families (tree daemon) with revoke, L1 rotation,
#         mgmt-auth and tamper; the pinned RELEASE artefacts × the default
#         families; and every censor scenario × one TCP and one QUIC family.
# full    every censor scenario × all 7 families; the whole lifecycle
#         (recipients, revoke, L1, L2, L3, freshness, mgmt-auth, capability
#         honesty, tamper, wrong credentials, repeated relay restarts) on the
#         tree daemon and again (bar the restarts) on
#         the pinned release artefacts; rotation under a censor; and the
#         pinned artefacts × all 7 families (FINDINGS F-002, kept visible);
#         and a relay provisioned with two opt-in families only (FAM-4).
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
    quick|full) mode="$1" ;;
    -j) jobs="$2"; shift ;;
    --only) only="$2"; shift ;;
    --plan) plan_only=1 ;;
    -h|--help) sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "e2e: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
if [[ -z "$jobs" ]]; then
  jobs=$(( $(nproc) / 2 )); (( jobs > 8 )) && jobs=8; (( jobs < 1 )) && jobs=1
fi

# ---- the plan: label <TAB> run.sh arguments ------------------------------
# The longest worlds first, so the short ones fill in around them.
scenarios=(); for f in "$RIG"/scenarios/*.json; do s="$(basename "$f" .json)"; [[ "$s" == clean ]] || scenarios+=("$s"); done
plan=()
if [[ "$mode" == quick ]]; then
  plan+=("clean"$'\t'"--mgmt=tree --ops revoke,l1,mgmtauth,tamper clean")
  plan+=("release"$'\t'"--ops revoke,mgmtauth clean @default")
  for s in "${scenarios[@]}"; do plan+=("$s"$'\t'"--mgmt=tree $s vless-reality hysteria2"); done
else
  plan+=("release.lifecycle"$'\t'"--ops lifecycle,tamper,wrongcreds clean @default")
  plan+=("clean.rotation"$'\t'"--mgmt=tree --ops l1,l2,l3,freshness,caps clean")   # l2 THEN l3: the cover host moves, then the address (naive, FINDINGS LC-3); the other order runs under udp-blackhole and in release.lifecycle
  plan+=("clean.recipients"$'\t'"--mgmt=tree --ops recipients,revoke,wrongcreds,tamper,mgmtauth,restarts clean")
  for s in "${scenarios[@]}"; do
    if [[ "$s" == udp-blackhole ]]; then
      plan+=("$s"$'\t'"--mgmt=tree --ops recipients,l1,l3,l2,caps $s")   # rotation under a censor
    else
      plan+=("$s"$'\t'"--mgmt=tree $s")
    fi
  done
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
