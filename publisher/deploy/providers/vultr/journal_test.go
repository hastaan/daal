package vultr

import (
	"context"
	"net"
	"testing"

	"daal/publisher/deploy/provider"
)

type recJournal struct {
	lines []string
}

func (r *recJournal) Begin(mode, relay string, port int, sni string) error {
	r.lines = append(r.lines, "begin:"+mode)
	return nil
}
func (r *recJournal) Intent(kind, name, id string) error {
	r.lines = append(r.lines, "intent:"+kind)
	return nil
}
func (r *recJournal) Created(kind, id, name string, ip net.IP) {
	r.lines = append(r.lines, "created:"+kind)
}
func (r *recJournal) Deleted(kind, id string) { r.lines = append(r.lines, "deleted:"+kind) }
func (r *recJournal) Phase(step string)       { r.lines = append(r.lines, "phase:"+step) }

func TestProvision_VultrJournalsFirewallThenInstance(t *testing.T) {
	f := newFakeVultr(t)
	j := &recJournal{}
	opts := mkOpts()
	opts.Journal = j
	mustProvision(t, f, opts)
	want := []string{
		"begin:create",
		"intent:ssh-key", "created:ssh-key",
		"intent:firewall", "created:firewall",
		"intent:server", "created:server",
		"deleted:ssh-key",
	}
	if len(j.lines) != len(want) {
		t.Fatalf("journal = %v, want %v", j.lines, want)
	}
	for i := range want {
		if j.lines[i] != want[i] {
			t.Fatalf("journal[%d] = %q, want %q (all: %v)", i, j.lines[i], want[i], j.lines)
		}
	}
}

func TestProvision_VultrCannotFinishOnAnExistingServer(t *testing.T) {
	f := newFakeVultr(t)
	opts := mkOpts()
	opts.ExistingServerID = "inst-1"
	_, err := f.provider(t).Provision(context.Background(), opts)
	if code, _ := provider.ProvisionErrorCode(err); code != provider.CodeResumeUnsupported {
		t.Fatalf("err = %v code %q, want resume_unsupported", err, code)
	}
}

func TestProvision_VultrRefusesAStrandedInstanceWithoutItsPort(t *testing.T) {
	f := newFakeVultr(t)
	f.instances["stranded"] = &wireInstance{
		ID: "stranded", Label: relayLabel(), Status: "active",
		Plan: testPlan, Region: testRegion, MainIP: "1.2.3.4",
		Tags: ownershipTags(relayLabel(), "iran-default"),
	}
	opts := mkOpts()
	opts.MgmtPort = 0
	_, err := f.provider(t).Provision(context.Background(), opts)
	code, sid := provider.ProvisionErrorCode(err)
	if code != provider.CodeServerExists || sid != "stranded" {
		t.Fatalf("err = %v code=%q id=%q, want server_exists naming the stranded instance", err, code, sid)
	}
	if len(f.instances) != 1 {
		t.Fatalf("%d instances after the refusal, want 1", len(f.instances))
	}
}
