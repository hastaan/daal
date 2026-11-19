#!/usr/bin/env python3
"""Apply the pin bump for a staged relay release to this tree.

    bash tools/release/relay-v1.5.1.sh          # stage (no upload)
    python3 tools/release/pin-bump.py            # this: steps 1-4 of README.md "The pin bump"

It edits files; it uploads nothing, commits nothing and runs no test.
Every edit is asserted: if the tree is not in the shape this script
expects it stops, and nothing it has not yet written is touched. Read
`git diff` afterwards, then do steps 5-9 of tools/release/README.md
(the golden, the proof, the upload, the rebuilds).

OLD and NEW are the tags; change them together with the release script
when the next release is cut.
"""
import json
import os
import sys

OLD, NEW = "relay-v1.5.0", "relay-v1.5.1"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Rig entries that say "fixed in the tree, not on a released relay".
RELEASED_FINDINGS = ("F-002", "LC-1", "INT-2", "F-005")
# Files that name the tag / staging directory of the PINNED artefacts.
TAGGED = [
    "test-rigs/worldbox/run.sh",
    "test-rigs/worldbox/driver/run.go",
    "test-rigs/worldbox/README.md",
    "test-rigs/worldbox/repro/int2-naive-alpn-race.sh",
    "cmd/daal-relay-mgmt/singbox_mux_test.go",
    "publisher/deploy/cloudinit/template_test.go",
    "publisher/deploy/providers/hetzner/cover_sni_singbox_test.go",
    ".github/workflows/gate.yml",
]


def die(msg):
    sys.exit("pin-bump: " + msg)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def main():
    staged = os.path.join(ROOT, "dist-release", NEW, "artifacts.snippet.go")
    if not os.path.isfile(staged):
        die("no %s — run tools/release/%s.sh first" % (staged, NEW))
    snippet = open(staged, encoding="utf-8").read()
    if NEW not in snippet or "daal-relay-mgmt" not in snippet:
        die("%s does not look like the %s snippet" % (staged, NEW))

    out = {}

    # 1. the pins and the gate that moves with them
    rel = "publisher/deploy/cloudinit/artifacts.go"
    s = read(rel)
    a = s.find("var V15Artifacts = ArtifactManifest{")
    b = s.find("// PinnedMgmtServesOptInFamilies says whether")
    if a < 0 or b < a:
        die(rel + ": cannot find the manifest block")
    if NEW in s[a:b]:
        die(rel + " already pins " + NEW)
    s = s[:a] + snippet.rstrip("\n") + "\n\n" + s[b:]
    gate = "const PinnedMgmtServesOptInFamilies = false"
    if s.count(gate) != 1:
        die(rel + ": PinnedMgmtServesOptInFamilies is not false exactly once")
    out[rel] = s.replace(gate, gate.replace("false", "true"))

    # 2. its TypeScript mirror
    rel = "client-ui/src/publisher/extraFamilies.ts"
    s = read(rel)
    gate = "export const RELEASED_RELAY_SERVES_EXTRA_FAMILIES = false;"
    if s.count(gate) != 1:
        die(rel + ": RELEASED_RELAY_SERVES_EXTRA_FAMILIES is not false exactly once")
    out[rel] = s.replace(gate, gate.replace("false", "true"))

    # 3. the findings a released relay no longer has
    rel = "test-rigs/worldbox/known-findings.json"
    known = json.loads(read(rel))
    have = {e["id"] for e in known}
    missing = [i for i in RELEASED_FINDINGS if i not in have]
    if missing:
        die("%s has no entry %s — already removed?" % (rel, ", ".join(missing)))
    for e in known:
        if e["id"] in RELEASED_FINDINGS and e.get("when", {}).get("box") != "pinned":
            die("%s: %s is not restricted to box=pinned; not deleting it blindly" % (rel, e["id"]))
    known = [e for e in known if e["id"] not in RELEASED_FINDINGS]
    out[rel] = json.dumps(known, indent=2, ensure_ascii=False) + "\n"

    # 4. every name of the pinned tag / staging directory
    for rel in TAGGED:
        if not os.path.isfile(os.path.join(ROOT, rel)):
            die(rel + " does not exist (moved? update TAGGED)")
        s = read(rel)
        if OLD not in s:
            die(rel + " does not mention " + OLD)
        out[rel] = s.replace(OLD, NEW)

    for rel, body in out.items():
        with open(os.path.join(ROOT, rel), "w", encoding="utf-8") as f:
            f.write(body)
        print("edited", rel)
    print("""
Now, by hand (tools/release/README.md, "The pin bump", steps 5-9):
  gofmt -w publisher/deploy/cloudinit/artifacts.go
  (cd publisher/deploy && go test ./cloudinit/)   # set TestRender_GoldenSHA256's `want` to the hash it prints
  mark REL-1, F-002, LC-1, INT-2 and the released-relay half of F-005 fixed in test-rigs/worldbox/FINDINGS.md
  ./daal test && ./daal e2e full                   # release.all-families all green, BEFORE uploading
  bash tools/release/%s.sh --upload      # same tree, same toolchain => same bytes
""" % NEW)


if __name__ == "__main__":
    main()
