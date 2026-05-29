#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="relay-v1.5.0"
MIRROR_TAG="relay-v1.5.0-mirror"
REPO="${DAAL_RELEASE_REPO:-hastaan/daal}"
KEY="${DAAL_RELEASE_KEY:-$ROOT/release-keys/release.key}"
OUT="$ROOT/dist-release/$TAG"
VENDOR="$ROOT/tools/vendor"
GO_BIN="${GO_BIN:-go}"
SING_BOX_VERSION="1.13.12"
SING_BOX_TARBALL="sing-box-$SING_BOX_VERSION-linux-amd64.tar.gz"
SING_BOX_TARBALL_SHA256="1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4"
SING_BOX_URL="https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/$SING_BOX_TARBALL"

usage() {
  cat <<USAGE
Usage: $0 [--upload]

Builds, signs, and stages relay artifacts under:
  $OUT

Set DAAL_RELEASE_KEY to override the private key path.
Set DAAL_RELEASE_REPO to override the GitHub repo.
USAGE
}

UPLOAD=0
for arg in "$@"; do
  case "$arg" in
    --upload) UPLOAD=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need openssl
need sha256sum
need awk
need od
need tr
need tar

if [[ ! -f "$KEY" ]]; then
  echo "release key not found: $KEY" >&2
  echo "run tools/release/keygen.sh first" >&2
  exit 1
fi

mkdir -p "$OUT/work" "$VENDOR"
rm -f "$OUT"/*.sig "$OUT"/*.sig.hex "$OUT"/*.sha256 "$OUT"/artifacts.snippet.go

build_go() {
  local pkg=$1
  local dst=$2
  (
    cd "$ROOT/$pkg"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build -trimpath -ldflags="-s -w" -o "$OUT/$dst" .
  )
}

stage_sing_box() {
  local tarball="$VENDOR/$SING_BOX_TARBALL"
  if [[ ! -f "$tarball" ]]; then
    need curl
    curl -fsSL "$SING_BOX_URL" -o "$tarball"
  fi
  local got
  got="$(sha256sum "$tarball" | awk '{print $1}')"
  if [[ "$got" != "$SING_BOX_TARBALL_SHA256" ]]; then
    echo "sing-box tarball sha256 mismatch: got $got want $SING_BOX_TARBALL_SHA256" >&2
    exit 1
  fi
  rm -rf "$OUT/work/sing-box"
  mkdir -p "$OUT/work/sing-box"
  tar -xzf "$tarball" -C "$OUT/work/sing-box"
  cp "$OUT/work/sing-box/sing-box-$SING_BOX_VERSION-linux-amd64/sing-box" "$OUT/sing-box-$SING_BOX_VERSION-linux-amd64"
  chmod 0755 "$OUT/sing-box-$SING_BOX_VERSION-linux-amd64"
}

sign_artifact() {
  local file=$1
  local sig="$file.sig"
  openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$file" -out "$sig"
  sha256sum "$file" | awk '{print $1}' > "$file.sha256"
  od -An -tx1 -v "$sig" | tr -d ' \n' > "$sig.hex"
  echo >> "$sig.hex"
}

url_for() {
  local tag=$1
  local name=$2
  printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$tag" "$name"
}

emit_snippet() {
  local snippet="$OUT/artifacts.snippet.go"
  {
    echo "var V15Artifacts = ArtifactManifest{"
    echo '	Version: "v1.5.0",'
    echo "	Artefacts: []Artifact{"
    emit_artifact "sing-box-$SING_BOX_VERSION-linux-amd64" "sing-box"
    emit_artifact "daal-relay-health-0.1.0-linux-amd64" "daal-relay-health"
    echo "	},"
    echo "}"
    echo
    echo "var V2Artifacts = ArtifactManifest{"
    echo '	Version: "v2.0.0",'
    echo "	Artefacts: []Artifact{"
    emit_artifact "sing-box-$SING_BOX_VERSION-linux-amd64" "sing-box"
    emit_artifact "daal-relay-health-0.1.0-linux-amd64" "daal-relay-health"
    emit_artifact "daal-relay-mgmt-0.1.0-linux-amd64" "daal-relay-mgmt"
    echo "	},"
    echo "}"
  } > "$snippet"
  echo "$snippet"
}

emit_artifact() {
  local name=$1
  local install_as=$2
  local sha
  local sig
  sha="$(cat "$OUT/$name.sha256")"
  sig="$(cat "$OUT/$name.sig.hex")"
  cat <<GO
		{
			Name:      "$name",
			InstallAs: "$install_as",
			Sha256:    "$sha",
			SigHex:    "$sig",
			Mirrors: []string{
				"$(url_for "$TAG" "$name")",
				"$(url_for "$MIRROR_TAG" "$name")",
			},
		},
GO
}

upload_release() {
  need gh
  local tag=$1
  shift
  if gh release view "$tag" --repo "$REPO" >/dev/null 2>&1; then
    gh release upload "$tag" --repo "$REPO" --clobber "$@"
  else
    gh release create "$tag" --repo "$REPO" --title "$tag" --notes "Daal relay artifacts $tag" "$@"
  fi
}

build_go "cmd/daal-relay-health" "daal-relay-health-0.1.0-linux-amd64"
build_go "cmd/daal-relay-mgmt" "daal-relay-mgmt-0.1.0-linux-amd64"
stage_sing_box

for artifact in \
  "$OUT/sing-box-$SING_BOX_VERSION-linux-amd64" \
  "$OUT/daal-relay-health-0.1.0-linux-amd64" \
  "$OUT/daal-relay-mgmt-0.1.0-linux-amd64"
do
  sign_artifact "$artifact"
done

emit_snippet

if [[ "$UPLOAD" -eq 1 ]]; then
  upload_release "$TAG" \
    "$OUT/sing-box-$SING_BOX_VERSION-linux-amd64" \
    "$OUT/daal-relay-health-0.1.0-linux-amd64" \
    "$OUT/daal-relay-mgmt-0.1.0-linux-amd64" \
    "$OUT/sing-box-$SING_BOX_VERSION-linux-amd64.sig" \
    "$OUT/daal-relay-health-0.1.0-linux-amd64.sig" \
    "$OUT/daal-relay-mgmt-0.1.0-linux-amd64.sig"
  upload_release "$MIRROR_TAG" \
    "$OUT/sing-box-$SING_BOX_VERSION-linux-amd64" \
    "$OUT/daal-relay-health-0.1.0-linux-amd64" \
    "$OUT/daal-relay-mgmt-0.1.0-linux-amd64" \
    "$OUT/sing-box-$SING_BOX_VERSION-linux-amd64.sig" \
    "$OUT/daal-relay-health-0.1.0-linux-amd64.sig" \
    "$OUT/daal-relay-mgmt-0.1.0-linux-amd64.sig"
fi
