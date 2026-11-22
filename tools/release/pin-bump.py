#!/usr/bin/env python3
"""Apply the pin bump for a staged relay release to this tree.

    bash tools/release/relay-v1.6.0.sh          # stage (no upload)
    python3 tools/release/pin-bump.py            # this: steps 1-4 of README.md "The pin bump"

It edits files; it uploads nothing, commits nothing and runs no test.
Every edit is asserted: if the tree is not in the shape this script
expects it stops, and nothing it has not yet written is touched. Read
`git diff` afterwards, then do steps 5-9 of tools/release/README.md
(the golden, the proof, the upload, the rebuilds).

OLD and NEW are the tags; change them together with the release script
when the next release is cut.

relay-v1.5.1 -> relay-v1.6.0: the opt-in-families gate
(PinnedMgmtServesOptInFamilies and its TypeScript mirror) was flipped by
the relay-v1.5.1 bump and stays true, so this bump only CHECKS it; and
no known-findings entry is restricted to box=pinned any more, so there
is nothing to delete there (RELEASED_FINDINGS is empty, and the file is
left alone).
"""
import json
import os
import sys

OLD, NEW = "relay-v1.5.1", "relay-v1.6.0"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Rig entries that say "fixed in the tree, not on a released relay"
# (box=pinned) and that this release fixes. None for relay-v1.6.0: the
# add-on worlds (standby, cdn-*) ran on the tree daemon and recorded no
# pinned-box finding; known-findings.json holds none with box=pinned.
RELEASED_FINDINGS = ()
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
# Mentions of OLD in TAGGED files that are history or a statement about
# that release, not the name of the pinned tag: kept exactly as they are.
KEEP = {
    "publisher/deploy/cloudinit/template_test.go": [
        "2026-11-19: the pin bump to relay-v1.5.1",
    ],
}
# Mentions whose sentence stops being true under a blind rename: reworded
# (each must occur exactly once) before the rename.
REWORD = {
    "test-rigs/worldbox/run.sh": [(
        "  # fingerprint only from a box that authenticates it, which the pinned\n"
        "  # relay-v1.5.1 health binary cannot. A tree world runs the tree's.\n",
        "  # fingerprint only from a box that authenticates it, which a pinned\n"
        "  # health binary older than the tree's need not do (relay-v1.5.0's\n"
        "  # could not). A tree world runs the tree's.\n",
    )],
}


def die(msg):
    sys.exit("pin-bump: " + msg)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def rename_tag(rel, s):
    for old, new in REWORD.get(rel, []):
        if s.count(old) != 1:
            die("%s: the passage to reword is not there exactly once:\n%s" % (rel, old))
        s = s.replace(old, new)
    keep = KEEP.get(rel, [])
    for i, k in enumerate(keep):
        if s.count(k) != 1:
            die("%s: the history line to keep is not there exactly once: %r" % (rel, k))
        s = s.replace(k, "\x00KEEP%d\x00" % i)
    if OLD not in s:
        die(rel + " does not mention " + OLD)
    s = s.replace(OLD, NEW)
    for i, k in enumerate(keep):
        s = s.replace("\x00KEEP%d\x00" % i, k)
    return s


def main():
    staged = os.path.join(ROOT, "dist-release", NEW, "artifacts.snippet.go")
    if not os.path.isfile(staged):
        die("no %s — run tools/release/%s.sh first" % (staged, NEW))
    snippet = open(staged, encoding="utf-8").read()
    if NEW not in snippet or "daal-relay-mgmt" not in snippet:
        die("%s does not look like the %s snippet" % (staged, NEW))

    out = {}

    # 1. the pins (the opt-in gate already serves them: checked, not flipped)
    rel = "publisher/deploy/cloudinit/artifacts.go"
    s = read(rel)
    a = s.find("var V15Artifacts = ArtifactManifest{")
    b = s.find("// PinnedMgmtServesOptInFamilies says whether")
    if a < 0 or b < a:
        die(rel + ": cannot find the manifest block")
    if NEW in s[a:b]:
        die(rel + " already pins " + NEW)
    if OLD not in s[a:b]:
        die(rel + " does not pin " + OLD + " — not the release this script bumps from")
    s = s[:a] + snippet.rstrip("\n") + "\n\n" + s[b:]
    if s.count("const PinnedMgmtServesOptInFamilies = true") != 1:
        die(rel + ": PinnedMgmtServesOptInFamilies is not true exactly once (it was flipped by the relay-v1.5.1 bump)")
    out[rel] = s

    # 2. its TypeScript mirror: must already agree
    rel = "client-ui/src/publisher/extraFamilies.ts"
    if read(rel).count("export const RELEASED_RELAY_SERVES_EXTRA_FAMILIES = true;") != 1:
        die(rel + ": RELEASED_RELAY_SERVES_EXTRA_FAMILIES is not true exactly once")

    # 3. the findings a released relay no longer has
    rel = "test-rigs/worldbox/known-findings.json"
    known = json.loads(read(rel))
    if RELEASED_FINDINGS:
        have = {e["id"] for e in known}
        missing = [i for i in RELEASED_FINDINGS if i not in have]
        if missing:
            die("%s has no entry %s — already removed?" % (rel, ", ".join(missing)))
        for e in known:
            if e["id"] in RELEASED_FINDINGS and e.get("when", {}).get("box") != "pinned":
                die("%s: %s is not restricted to box=pinned; not deleting it blindly" % (rel, e["id"]))
        known = [e for e in known if e["id"] not in RELEASED_FINDINGS]
        out[rel] = json.dumps(known, indent=2, ensure_ascii=False) + "\n"
    else:
        pinned = [e["id"] for e in known if e.get("when", {}).get("box") == "pinned"]
        if pinned:
            die("%s has box=pinned entries %s and RELEASED_FINDINGS is empty — decide which this release fixes"
                % (rel, ", ".join(pinned)))

    # 4. every name of the pinned tag / staging directory
    for rel in TAGGED:
        if not os.path.isfile(os.path.join(ROOT, rel)):
            die(rel + " does not exist (moved? update TAGGED)")
        out[rel] = rename_tag(rel, read(rel))

    for rel, body in out.items():
        with open(os.path.join(ROOT, rel), "w", encoding="utf-8") as f:
            f.write(body)
        print("edited", rel)
    print("""
Now, by hand (tools/release/README.md, "The pin bump", steps 5-9):
  gofmt -w publisher/deploy/cloudinit/artifacts.go
  the RELEASE COUPLING notes in artifacts.go: what %s carries
  (cd publisher/deploy && go test ./cloudinit/)   # set TestRender_GoldenSHA256's `want` to the hash it prints, with a dated line
  ./daal test && ./daal e2e full                   # the release worlds green, BEFORE uploading
  (cd test-rigs/worldbox && ./e2e.sh addons -j 1)  # and the add-on worlds; standby and cdn-* on the pinned box too
  bash tools/release/%s.sh --upload      # same tree, same toolchain => same bytes
""" % (NEW, NEW))


if __name__ == "__main__":
    main()
