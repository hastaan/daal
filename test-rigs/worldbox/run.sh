#!/usr/bin/env bash
# worldbox — a whole Daal world on one machine: rootless, hermetic, seconds.
#
#   ./run.sh <scenario> [family…]          e.g.  ./run.sh clean vless-reality
#   ./run.sh --ops revoke,wrongcreds clean vless-reality
#   ./run.sh --json clean                  one JSON line per check on stdout
#   ./run.sh --shell clean vless-reality   poke around inside the world afterwards
#   ./run.sh --list                        scenarios, families, ops
#   ./run.sh --mgmt=tree clean             run THIS TREE's daal-relay-mgmt and daal-relay-health instead of the pinned release
#
#   ./run.sh clean @default               the families a relay serves by default
#
# This is ONE world. ./e2e.sh (and `./daal e2e`) runs the whole matrix of
# them and folds the results into one report.
#
# Exit status:
#    0  nothing unexpected: every check matched its expectation, or is red
#       for an OPEN finding listed in known-findings.json (reported KNOWN)
#    1  an unexpected red check, or a known finding that did not reproduce
#    2  the rig itself could not start (build failure, bad arguments)
#   77  SKIPPED: this machine cannot host the rig (no unprivileged user
#       namespaces, no subuid range, a missing tool or release artefact).
#       Never a pass: callers must say so loudly.
#
# This script only builds and enters the namespaces. Everything else is
# driver/ (see README.md).
set -euo pipefail

RIG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$RIG/../.." && pwd)"
BIN="${WB_BIN:-$RIG/bin}"
ART="${WB_ARTIFACTS:-$REPO/dist-release/relay-v1.5.1}"
# The tag set tools/build-engine-android.sh ships (minus cshared): naive is
# part of the phone's engine, so it is part of the lab's.
ENGINE_TAGS="singbox,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_naive_outbound,with_purego"
export GOCACHE="${GOCACHE:-/tmp/daal-go-build}"
export GOFLAGS="${GOFLAGS:-} -mod=mod"

mgmt=pinned
build_only=""
preflight_only=""
pass=()
for a in "$@"; do
  case "$a" in
    --mgmt=tree)   mgmt=tree ;;
    --mgmt=pinned) mgmt=pinned ;;
    --build-only)  build_only=1 ;;
    --preflight)   preflight_only=1 ;;
    --list)        mkdir -p "$BIN"; (cd "$RIG/driver" && go build -o "$BIN/wb" .); exec "$BIN/wb" list "$RIG" ;;
    -h|--help)     sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)             pass+=("$a") ;;
  esac
done

die() { echo "worldbox: $*" >&2; exit 2; }
# cannot: this MACHINE cannot host the rig. Distinct from a failure (the
# rig is not broken and Daal was not tested) and from a pass.
cannot() {
  {
    echo "worldbox: ============================ SKIPPED ============================"
    echo "worldbox: the end-to-end rig CANNOT RUN on this machine: $*"
    echo "worldbox: NOTHING was tested. This is not a pass."
    echo "worldbox: ==================================================================="
  } >&2
  exit 77
}

# ---- preflight: say exactly what is missing, never half-run -------------
for t in go gcc unshare ip nft tc python3 openssl ss flock timeout; do
  command -v "$t" >/dev/null || cannot "missing tool: $t"
done
python3 -c 'import yaml' 2>/dev/null || cannot "python3 needs PyYAML (the box's cloud-init stand-in parses the real user-data with it)"
unshare -Urn true 2>/dev/null || cannot "unprivileged user namespaces are not available (kernel.unprivileged_userns_clone / an AppArmor userns restriction)"
# The client namespace needs more than one uid: Android captures traffic
# into a VPN per-uid and excludes the VPN app's own uid, and the rig does
# the same (the engine is uid 0, the probing "app" is uid 10100).
unshare --map-root-user --map-auto true 2>/dev/null || cannot "need a subordinate uid/gid range for $(id -un) (newuidmap + an entry in /etc/subuid and /etc/subgid)"
[[ -c /dev/net/tun ]] || cannot "/dev/net/tun is missing"
# The censor's rules live in a network namespace of our own; they need the
# kernel's nftables, conntrack (the wire tap) and NFQUEUE (the payload box).
unshare -Urn sh -c 'nft add table inet wb_pre && nft add chain inet wb_pre f "{ type filter hook forward priority 0; }" && nft add rule inet wb_pre f ct state new counter && nft add rule inet wb_pre f tcp dport 1 queue num 1' 2>/dev/null \
  || cannot "nftables with conntrack and NFQUEUE is not usable inside a user namespace (modules nf_tables, nf_conntrack, nfnetlink_queue)"
for f in sing-box-1.13.12-linux-amd64 daal-relay-mgmt-0.1.0-linux-amd64 daal-relay-health-0.1.0-linux-amd64; do
  [[ -f "$ART/$f" ]] || cannot "release artefact $ART/$f is missing — stage the release this tree pins: gh release download relay-v1.5.1 --dir $ART (see tools/release/README.md)"
done
[[ -n "$preflight_only" ]] && { echo "worldbox: this machine can host the rig"; exit 0; }

# ---- build: the real binaries, from this tree ---------------------------
# WB_NO_BUILD=1 skips it (the binaries in $BIN are used as they are) and
# --build-only stops after it: together with WB_BIN they let several worlds
# run side by side without one start relinking — or, for libcronet.so,
# deleting — what another is executing. censor-matrix.sh does exactly that.
mkdir -p "$BIN"
if [[ -z "${WB_NO_BUILD:-}" ]]; then
build() { # dir out [go build args…]
  local dir="$1" out="$2"; shift 2
  (cd "$dir" && go build "$@" -o "$BIN/$out" .) || die "build failed: $out"
}
build "$RIG/driver"            wb
build "$RIG/labclient"         wb-client   -tags "$ENGINE_TAGS"
build "$REPO/cmd/daal-deploy"  daal-deploy
# naive rides Cronet, loaded at run time (with_purego) from beside the
# binary — the APK ships it in lib/<abi>/. sing-box's own dependency,
# cronet-go, carries a prebuilt linux/amd64 libcronet.so as a Go module;
# take exactly the version the engine's go.mod resolves, from the module
# cache (no network). If it is not there the naive family is reported
# SKIPPED with this reason — never silently absent.
# Replaced atomically (never removed first): another world may be starting
# a client out of this directory right now.
cronet_dir="$(cd "$RIG/labclient" && GOFLAGS=-mod=mod GOPROXY=off go list -m -f '{{.Dir}}' "github.com/sagernet/cronet-go/lib/linux_$(go env GOARCH)" 2>/dev/null || true)"
if [[ -n "$cronet_dir" && -f "$cronet_dir/libcronet.so" ]]; then
  install -m 0755 "$cronet_dir/libcronet.so" "$BIN/.libcronet.so.$$" && mv -f "$BIN/.libcronet.so.$$" "$BIN/libcronet.so"
  rm -f "$BIN/cronet.missing"
else
  rm -f "$BIN/libcronet.so"
  echo "no libcronet.so for linux/$(go env GOARCH) in the Go module cache (module github.com/sagernet/cronet-go/lib/linux_$(go env GOARCH), which the engine's go.mod pins); run 'go mod download' once in $RIG/labclient" > "$BIN/cronet.missing"
fi
if [[ "$mgmt" == tree ]]; then
  (cd "$REPO/cmd/daal-relay-mgmt" && CGO_ENABLED=0 go build -o "$BIN/daal-relay-mgmt.tree" .) || die "build failed: daal-relay-mgmt"
  # The health endpoint is the other half of the provisioning bootstrap
  # (publisher/deploy/health): the tree's publisher pins a management
  # fingerprint only from a box that authenticates it, which the pinned
  # relay-v1.5.1 health binary cannot. A tree world runs the tree's.
  (cd "$REPO/cmd/daal-relay-health" && CGO_ENABLED=0 go build -o "$BIN/daal-relay-health.tree" .) || die "build failed: daal-relay-health"
fi
fi # WB_NO_BUILD
override=()
if [[ "$mgmt" == tree ]]; then
  [[ -x "$BIN/daal-relay-mgmt.tree" ]] || die "WB_NO_BUILD is set but $BIN/daal-relay-mgmt.tree does not exist"
  [[ -x "$BIN/daal-relay-health.tree" ]] || die "WB_NO_BUILD is set but $BIN/daal-relay-health.tree does not exist"
  override=(--override "daal-relay-mgmt=$BIN/daal-relay-mgmt.tree,daal-relay-health=$BIN/daal-relay-health.tree")
fi
[[ -x "$BIN/wb" && -x "$BIN/wb-client" && -x "$BIN/daal-deploy" ]] || die "WB_NO_BUILD is set but $BIN is not fully built"
[[ -n "$build_only" ]] && { echo "worldbox: built into $BIN"; exit 0; }

# ---- evidence directory -------------------------------------------------
RUN="$RIG/out/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$RUN"
ln -sfn "$RUN" "$RIG/out/latest" 2>/dev/null || true   # a convenience; two simultaneous starts may race for it
# Keep the newest runs (WB_KEEP_RUNS, default 10) — but never delete the
# directory of a world that is still running: several run.sh may be going
# at once (censor-matrix.sh -j, or two people), and a slow scenario would
# otherwise have its evidence pulled from under it by a later start. This
# shell is exec'd into the world below, so $$ lives exactly as long as it.
echo "$$" >"$RUN/.running"
# Pruning is best-effort and serialised: two starts pruning at once would
# each see the other's deletions as `ls` errors (which, under pipefail and
# errexit, used to kill a starting world silently with exit 2).
(
  flock -n 9 || exit 0   # somebody else is pruning right now; that is enough
  { ls -1dt "$RIG"/out/2* 2>/dev/null || true; } | tail -n +$(( ${WB_KEEP_RUNS:-10} + 1 )) | while read -r old; do
    pid="$(cat "$old/.running" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then continue; fi
    rm -rf "$old" 2>/dev/null || true
  done
) 9>"$RIG/out/.prune.lock" || true

# ---- enter the world ----------------------------------------------------
# user+net+mount+pid namespaces, the driver as PID 1. Teardown is the
# kernel's job, not ours: when PID 1 exits — pass, fail, panic, SIGKILL,
# Ctrl-C (--kill-child) — every process in the pid namespace is killed,
# and the network and mount namespaces vanish with the last of them.
# Nothing is created outside these namespaces except files under out/.
exec unshare --user --map-root-user --map-auto --net --mount --pid --fork --kill-child \
     --mount-proc --propagation private \
     "$BIN/wb" run --repo "$REPO" --rig "$RIG" --bin "$BIN" --run-dir "$RUN" \
     --artifacts "$ART" "${override[@]}" "${pass[@]}"
