#!/usr/bin/env bash
# tools/watch-appveyor.sh — poll the AppVeyor v0.1.0.15 build, and as
# each job (windows/macos/ios) reaches a finished state, pull the
# artifacts via the AppVeyor REST API and `gh release upload --clobber`
# them to v0.1.0.
#
# Stops automatically when all 3 jobs are in a terminal state.
#
# Usage:
#   bash tools/watch-appveyor.sh
#
# Polls every 60s.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist-release/v0.1.0"
mkdir -p "$DIST"

# Map artifact basenames to AppVeyor's nested release-assets\ paths.
# AppVeyor stores them as e.g. "release-assets\Daal_0.1.0_x64-setup.exe"
# (Windows uses backslash in the JSON `fileName` field) or
# "release-assets/Daal_0.1.0.dmg" (mac/ios use forward slash).
declare -a WIN_FILES=("Daal_0.1.0_x64-setup.exe" "Daal_0.1.0_x64.msi")
declare -a MAC_FILES=("Daal_0.1.0_universal.dmg" "Daal_0.1.0_universal.app.zip")
declare -a IOS_FILES=("Daal_0.1.0.ipa")

declare -A DONE   # jobId -> 1 once we've pulled artifacts

while true; do
    json="$(curl -sS https://ci.appveyor.com/api/projects/hastaan/daal)"
    overall="$(echo "$json" | python3 -c 'import sys,json; print(json.load(sys.stdin)["build"]["status"])')"
    echo "[$(date +%H:%M:%S)] build $overall"

    while IFS=$'\t' read -r jid status name; do
        echo "  job $jid  $status  ${name:0:55}"
        case "$status" in
            success|failed)
                if [ -z "${DONE[$jid]:-}" ]; then
                    echo "  -> pulling artifacts for $jid"
                    artifacts_json="$(curl -sS "https://ci.appveyor.com/api/buildjobs/$jid/artifacts")"
                    echo "$artifacts_json" | python3 -c '
import sys,json,urllib.parse
for a in json.load(sys.stdin):
    fn=a["fileName"]
    # encode the inner "release-assets/" + filename as-is
    print(urllib.parse.quote(fn, safe=""), fn.split("/")[-1].split("\\")[-1])
' | while read -r enc name; do
                        url="https://ci.appveyor.com/api/buildjobs/$jid/artifacts/$enc"
                        echo "     GET $name"
                        curl -sSL -o "$DIST/$name" "$url"
                    done
                    # Refresh sha256sum
                    (cd "$DIST" && \
                     sha256sum $(ls *.deb *.rpm *.AppImage *.apk *.exe *.msi *.dmg *.zip *.ipa 2>/dev/null) > daal-v0.1.0.sha256sum)
                    # Upload to GH Release
                    gh release upload v0.1.0 "$DIST"/* --clobber 2>&1 | tail -3 || true
                    DONE[$jid]=1
                fi
                ;;
        esac
    done < <(echo "$json" | python3 -c '
import sys,json
for j in json.load(sys.stdin)["build"]["jobs"]:
    print(j["jobId"], j["status"], j.get("name",""), sep="\t")')

    if [ "$overall" = "success" ] || [ "$overall" = "failed" ]; then
        echo "[$(date +%H:%M:%S)] overall=$overall — exiting"
        exit 0
    fi
    sleep 60
done
