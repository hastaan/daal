#!/usr/bin/env bash
# FINDINGS.md INT-2, reproduced with nothing of Daal in the loop: the
# released sing-box binary, one naive inbound, loopback, and openssl as
# the client. Each iteration starts sing-box, offers ALPN h2 on the naive
# TCP port, and stops it. An instance that answers with the fatal alert
# no_application_protocol (120) lost sing-box's start-up race and would
# refuse every Daal naive client until its next restart.
#
#   ./int2-naive-alpn-race.sh            # as an old daemon wrote naive-in: no alpn key
#   ./int2-naive-alpn-race.sh pinned     # as the tree daemon writes it: "alpn": ["h2","h3"]
#
# Measured 2026-11-18, 12 workers x 250 starts: 3 dead instances of 3000
# without the key, 0 of 3000 with it. The race needs real parallelism;
# on an idle machine with few workers expect fewer hits.
# Env: WORKERS (12), STARTS (250), SING_BOX (the pinned release binary).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
SB="${SING_BOX:-$here/../../../dist-release/relay-v1.5.1/sing-box-1.13.12-linux-amd64}"
[ -x "$SB" ] || { echo "no sing-box at $SB (stage the pinned release under dist-release/relay-v1.5.1 — see tools/release/README.md — or set SING_BOX)" >&2; exit 2; }
alpn=""; [ "${1:-}" = pinned ] && alpn=',"alpn":["h2","h3"]'
W="${WORKERS:-12}"; N="${STARTS:-250}"
T="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/k.pem" -out "$T/c.pem" \
  -days 2 -subj /CN=lab -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null || exit 2

worker() {
  local id=$1 port=$((28000 + $1)) ok=0 dead=0 other=0 p o
  cat > "$T/c$id.json" <<J
{"log":{"level":"error"},"inbounds":[{"type":"naive","tag":"naive-in","listen":"127.0.0.1","listen_port":$port,
 "users":[{"username":"u","password":"p"}],
 "tls":{"enabled":true$alpn,"certificate_path":"$T/c.pem","key_path":"$T/k.pem"}}],"outbounds":[{"type":"direct"}]}
J
  for _ in $(seq "$N"); do
    "$SB" run -c "$T/c$id.json" >/dev/null 2>&1 & p=$!
    for _ in $(seq 200); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break; sleep 0.01; done
    o="$(timeout 3 openssl s_client -alpn h2 -connect "127.0.0.1:$port" </dev/null 2>&1)"
    if grep -q 'ALPN protocol: h2' <<<"$o"; then ok=$((ok + 1))
    elif grep -q 'alert no application protocol' <<<"$o"; then dead=$((dead + 1))
    else other=$((other + 1)); fi
    kill "$p" 2>/dev/null; wait "$p" 2>/dev/null
  done
  echo "$ok $dead $other" > "$T/r$id"
}
for id in $(seq "$W"); do worker "$id" & done; wait
ok=0; dead=0; other=0
for id in $(seq "$W"); do read -r a b c < "$T/r$id"; ok=$((ok + a)); dead=$((dead + b)); other=$((other + c)); done
echo "starts=$((W * N))  served_h2=$ok  dead(alert 120)=$dead  other=$other  naive-in alpn key: $([ -n "$alpn" ] && echo present || echo absent)"
[ "$dead" -eq 0 ] && [ "$other" -eq 0 ]
