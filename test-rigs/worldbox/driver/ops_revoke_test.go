package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The revoked recipient's `blocked` counts as revocation only when the
// family was serving the bystander right after (FINDINGS INT-2: once,
// naive refused everybody and the revoked cell was green for the wrong
// reason). The unattributable case must be red, and must not be something
// known-findings.json excuses — not even with INT-2's own signature in
// the detail and INT-2's full matrix budget available.
func TestRevokedBlockedIsNotCountedWhenTheBystanderFailsToo(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	newRC := func(expect string) *RunCtx {
		f, err := os.Create(filepath.Join(t.TempDir(), "results.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		rc := &RunCtx{Ctx: context.Background(), P: Paths{Run: t.TempDir()},
			R: &Results{run: "t", scenario: "clean", file: f, human: io.Discard, box: BoxTree, known: ks}}
		rc.Scn.Name = "clean"
		rc.Scn.Expect = map[string]string{"*": expect}
		return rc
	}
	naive := Family{Name: "naive"}

	rc := newRC(Pass)
	rc.R.note = " | engine stderr: handshake failed; returned -1, SSL error code 1, net_error -107"
	rc.revokedAttributable(naive, "op:revoke", Blocked, Blocked)
	if len(rc.R.all) != 1 {
		t.Fatalf("want one check, got %+v", rc.R.all)
	}
	c := rc.R.all[0]
	if c.OK || c.Check != "revoked.attributable" || c.Family != "naive" || !strings.Contains(c.Detail, "not evidence of revocation") {
		t.Fatalf("an unattributable `blocked` must be a red revoked.attributable: %+v", c)
	}
	if c.Known != "" {
		t.Fatalf("no finding may excuse it, got KNOWN [%s]", c.Known)
	}
	if _, ok := c.Evidence["shim_journal"]; !ok {
		t.Fatalf("the red check must say where the shim's lifecycle journal is: %+v", c.Evidence)
	}
	if v := Judge(ks, rc.R.all); v.OK() || len(v.Unexpected) != 1 {
		t.Fatalf("the run must fail: %+v", v)
	}

	// The bystander got through: the family was serving, the block is the revoke's.
	rc = newRC(Pass)
	rc.revokedAttributable(naive, "op:revoke", Blocked, Pass)
	if len(rc.R.all) != 1 || !rc.R.all[0].OK {
		t.Fatalf("%+v", rc.R.all)
	}
	// The revoked recipient was NOT blocked: revoked.tunnel is red already; nothing to attribute.
	rc = newRC(Pass)
	rc.revokedAttributable(naive, "op:revoke", Pass, Pass)
	// Under a scenario that blocks the family, both sessions are expected blocked.
	rc2 := newRC(Blocked)
	rc2.revokedAttributable(naive, "op:revoke", Blocked, Blocked)
	if len(rc.R.all) != 0 || len(rc2.R.all) != 0 {
		t.Fatalf("no check expected: %+v %+v", rc.R.all, rc2.R.all)
	}
}
