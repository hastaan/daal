#!/bin/sh
# Re-mints the byte fixtures freshness_wire_test.go and
# freshness_rotation_wire_test.go read, with the REAL publisher CLI.
#
#   core/abi/testdata/mint-freshness-fixtures.sh        (from anywhere)
#
# The fixtures are real publisher output on purpose (see the header of
# freshness_wire_test.go): a builder in this module would re-implement
# the publisher's encoder and the tests would stop seeing the seam.
#
# What is minted, and what each file IS:
#
#   freshness-3mirrors.sbp           a RECIPIENT's pack: bind-and-sign's
#                                    output with one recipient's
#                                    credentials rewritten in by
#                                    users-pack-sbp. What a phone holds.
#   freshness-3mirrors-rotated.sbp   the SIGNED, CREDENTIAL-LESS pack
#                                    bind-and-sign produces after an L3
#                                    address move. What the publisher
#                                    puts on the freshness mirrors.
#   freshness-doc-current.json       document for the pre-rotation pack
#   freshness-doc-rotated.json       document for the rotated pack,
#                                    superseding the pre-rotation id
#   freshness-doc-foreign.json       the rotated pack WITHOUT supersedes
#
# The key is generated here and thrown away: after a re-mint, paste the
# three values this script prints into freshness_rotation_wire_test.go.
# The credentials and the certificate are made up; no host is real.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

(cd "$repo/cmd/daal-deploy" && go build -o "$tmp/daal-deploy" .)
dd="$tmp/daal-deploy"

# Ed25519 keypair in the CLI's raw form: priv = seed||pub (64 bytes).
openssl genpkey -algorithm ed25519 -outform DER -out "$tmp/k.der"
tail -c 32 "$tmp/k.der" > "$tmp/seed"
openssl pkey -inform DER -in "$tmp/k.der" -pubout -outform DER | tail -c 32 > "$tmp/pub.bin"
cat "$tmp/seed" "$tmp/pub.bin" > "$tmp/priv.bin"
pubhex="$(od -An -tx1 -v "$tmp/pub.bin" | tr -d ' \n')"

"$dd" provision --dry-run --pubkey-file "$tmp/pub.bin" --region fsn1 \
    --toolbox-profile iran-default --helper-ip 203.0.113.9 -o "$tmp/rec.json" >/dev/null

# The relay's data-plane certificate, as cloud-init mints it: the
# first-boot address and one stable DNS name.
ip="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_ip"])' "$tmp/rec.json")"
cover="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["cover_sni"])' "$tmp/rec.json")"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$tmp/tls-key.pem" \
    -out "$tmp/tls-cert.pem" -days 3650 -nodes -subj /CN=daal-relay \
    -addext "subjectAltName=IP:${ip},DNS:${cover}" 2>/dev/null
pin="$(openssl x509 -in "$tmp/tls-cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64)"

# One recipient's reply from the relay (users-provision's shape).
python3 - "$tmp/tls-cert.pem" "$pin" "$cover" > "$tmp/creds.json" <<'PY'
import json, sys
print(json.dumps({
    "name": "r1",
    "vless_uuid": "11111111-2222-3333-4444-555555555555",
    "reality_short_id": "deadbeef",
    "reality_public_key": "Zml4dHVyZS1yZWFsaXR5LXB1YmxpYy1rZXktMzJieXRlcw",
    "hy2_password": "fixture-hy2-password",
    "naive_password": "fixture-naive-password",
    "ws_path": "/r1/cafebabe",
    "tls_cert_sha256": sys.argv[2],
    "tls_cert_pem": open(sys.argv[1]).read(),
    "cover_sni": sys.argv[3],
}))
PY

sign() { # record out
    "$dd" bind-and-sign --operator-record "$1" --priv-key "$tmp/priv.bin" --output "$2" \
        --endpoint-creds "$tmp/creds.json" --expiry-days 3650 --now-unix 1755388800 \
        --freshness-mirror ghpages=https://freshness.pages.invalid/f/abc.json \
        --freshness-mirror r2=https://cdn-r2.invalid/daal/f/abc.json \
        --freshness-mirror bunny=https://b-cdn.invalid/daal/freshness/abc.json \
        --revocation-url https://revoke.invalid/daal/rev.json \
        --revocation-pub-hex "$pubhex"
}
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

sign "$tmp/rec.json" "$tmp/signed.sbp" > "$tmp/signed.json"
"$dd" users-pack-sbp --in "$tmp/signed.sbp" --out "$here/freshness-3mirrors.sbp" \
    --creds-file "$tmp/creds.json" --server "$ip" >/dev/null

# An L3: only public_ip and the candidates' public_ip:* tags move,
# exactly what provider.AdoptPublicIP does to the record.
python3 - "$tmp/rec.json" "$tmp/rec-rotated.json" <<'PY'
import json, sys
rec = json.load(open(sys.argv[1]))
new = "203.0.113.201"
rec["public_ip"] = new
for c in rec["candidates"]:
    c["public_risk_tags"] = [("public_ip:" + new) if t.startswith("public_ip:") else t for t in c["public_risk_tags"]]
json.dump(rec, open(sys.argv[2], "w"))
PY
sign "$tmp/rec-rotated.json" "$here/freshness-3mirrors-rotated.sbp" > "$tmp/rotated.json"

old_id="$(field "$tmp/signed.json" relay_pack_id)"; old_sha="$(field "$tmp/signed.json" sbp_sha256)"
new_id="$(field "$tmp/rotated.json" relay_pack_id)"; new_sha="$(field "$tmp/rotated.json" sbp_sha256)"

doc() { # out pack-id sha now seq [extra…]
    out="$1"; id="$2"; sha="$3"; now="$4"; shift 4
    "$dd" publish-freshness --relay-pack-id "$id" --current-bundle-sha256 "$sha" \
        --current-signed-url https://cdn-r2.invalid/daal/packs/abc.sbp \
        --publisher-pub-hex "$pubhex" --root-priv-file "$tmp/priv.bin" \
        --now-unix "$now" --sequence "$now" --ttl-hours 87600 --out-file "$out" "$@" >/dev/null 2>&1 || true
    test -s "$out"
}
all="--mirror ghpages=https://freshness.pages.invalid/f/abc.json --mirror r2=https://cdn-r2.invalid/daal/f/abc.json --mirror bunny=https://b-cdn.invalid/daal/freshness/abc.json"
# shellcheck disable=SC2086
doc "$here/freshness-doc-current.json" "$old_id" "$old_sha" 1755388800 $all
# shellcheck disable=SC2086
doc "$here/freshness-doc-rotated.json" "$new_id" "$new_sha" 1755392400 $all --supersedes "$old_id"
doc "$here/freshness-doc-foreign.json" "$new_id" "$new_sha" 1755392400 \
    --mirror ghpages=https://freshness.pages.invalid/f/abc.json --mirror r2=https://cdn-r2.invalid/daal/f/abc.json

echo "fixturePubHex        = \"$pubhex\""
echo "fixturePackID        = \"$old_id\""
echo "fixtureRotatedPackID = \"$new_id\""
echo "fixtureRotatedServer = \"203.0.113.201\"   (was $ip)"
