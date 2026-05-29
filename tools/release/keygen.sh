#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEY_DIR="$ROOT/release-keys"
KEY="$KEY_DIR/release.key"
PUB="$KEY_DIR/release.pub"

mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
umask 077

if [[ -e "$KEY" ]]; then
  echo "release key already exists: $KEY" >&2
else
  openssl genpkey -algorithm ed25519 -out "$KEY"
fi

openssl pkey -in "$KEY" -pubout -out "$PUB" >/dev/null 2>&1

echo "public key PEM:"
cat "$PUB"
echo
echo "public key DER sha256:"
openssl pkey -pubin -in "$PUB" -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
