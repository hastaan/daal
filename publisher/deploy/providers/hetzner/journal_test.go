package hetzner

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/provjournal"
	"daal/publisher/deploy/relayports"
)

// orderLog interleaves cloud calls ("C:<method>") with journal writes
// ("J:<ev>:<kind>") in the order they happened, so the journal's one
// promise — intent before each create, created before the next call —
// can be checked against a real Provision run.
type orderLog struct{ lines []string }

func (o *orderLog) add(s string) { o.lines = append(o.lines, s) }

type loggingClient struct {
	*fakeClient
	log *orderLog
}

func (l *loggingClient) ServerByName(ctx context.Context, name string) (*ServerInfo, error) {
	l.log.add("C:ServerByName")
	return l.fakeClient.ServerByName(ctx, name)
}
func (l *loggingClient) ServerCreate(ctx context.Context, o ServerCreateOpts) (*ServerInfo, error) {
	l.log.add("C:ServerCreate")
	return l.fakeClient.ServerCreate(ctx, o)
}
func (l *loggingClient) ServerRebuild(ctx context.Context, id, img, ud string) (*ServerInfo, error) {
	l.log.add("C:ServerRebuild")
	return l.fakeClient.ServerRebuild(ctx, id, img, ud)
}
func (l *loggingClient) SSHKeyCreate(ctx context.Context, name string, pub []byte, labels map[string]string) (string, error) {
	l.log.add("C:SSHKeyCreate")
	return l.fakeClient.SSHKeyCreate(ctx, name, pub, labels)
}
func (l *loggingClient) SSHKeyDelete(ctx context.Context, id string) error {
	l.log.add("C:SSHKeyDelete")
	return l.fakeClient.SSHKeyDelete(ctx, id)
}
func (l *loggingClient) SSHKeyList(ctx context.Context) ([]SSHKeyInfo, error) {
	l.log.add("C:SSHKeyList")
	return l.fakeClient.SSHKeyList(ctx)
}
func (l *loggingClient) FirewallEnsureForServer(ctx context.Context, id string, ports []relayports.Endpoint) (string, error) {
	l.log.add("C:FirewallEnsureForServer")
	return l.fakeClient.FirewallEnsureForServer(ctx, id, ports)
}
func (l *loggingClient) ServerDelete(ctx context.Context, id string) error {
	l.log.add("C:ServerDelete")
	return l.fakeClient.ServerDelete(ctx, id)
}

// recJournal records every journal call into the same log, and can be
// told to fail an intent of one kind.
type recJournal struct {
	log        *orderLog
	failIntent string
	begins     []string
	created    map[string][]string
	deleted    map[string][]string
}

func newRecJournal(log *orderLog) *recJournal {
	return &recJournal{log: log, created: map[string][]string{}, deleted: map[string][]string{}}
}

func (r *recJournal) Begin(mode, relay string, port int, sni string) error {
	r.log.add("J:begin:" + mode)
	r.begins = append(r.begins, mode)
	return nil
}
func (r *recJournal) Intent(kind, name, id string) error {
	if kind == r.failIntent {
		return errors.New("disk full")
	}
	r.log.add("J:intent:" + kind)
	return nil
}
func (r *recJournal) Created(kind, id, name string, ip net.IP) {
	r.log.add("J:created:" + kind)
	r.created[kind] = append(r.created[kind], id)
}
func (r *recJournal) Deleted(kind, id string) {
	r.log.add("J:deleted:" + kind)
	r.deleted[kind] = append(r.deleted[kind], id)
}
func (r *recJournal) Phase(step string) { r.log.add("J:phase:" + step) }

var createCalls = map[string]string{
	"C:SSHKeyCreate":            provider.KindSSHKey,
	"C:ServerCreate":            provider.KindServer,
	"C:ServerRebuild":           provider.JournalKindRebuild,
	"C:FirewallEnsureForServer": provider.KindFirewall,
}

// assertJournalOrder: every create call is preceded by an intent of its
// kind (since the previous create), and the next cloud call after a
// create only happens once a created line of that kind is written.
func assertJournalOrder(t *testing.T, lines []string) {
	t.Helper()
	pendingIntent := map[string]bool{}
	awaitingCreated := ""
	for i, l := range lines {
		if strings.HasPrefix(l, "J:intent:") {
			pendingIntent[strings.TrimPrefix(l, "J:intent:")] = true
			continue
		}
		if strings.HasPrefix(l, "J:created:") {
			if awaitingCreated == strings.TrimPrefix(l, "J:created:") {
				awaitingCreated = ""
			}
			continue
		}
		if !strings.HasPrefix(l, "C:") {
			continue
		}
		if awaitingCreated != "" {
			t.Fatalf("cloud call %q at %d happened before the %s it follows was journalled as created:\n%s",
				l, i, awaitingCreated, strings.Join(lines, "\n"))
		}
		if kind, ok := createCalls[l]; ok {
			if !pendingIntent[kind] {
				t.Fatalf("create call %q at %d has no intent line before it:\n%s", l, i, strings.Join(lines, "\n"))
			}
			delete(pendingIntent, kind)
			awaitingCreated = kind
		}
	}
}

func TestProvisionJournal_IntentBeforeEachCreateCreatedBeforeNextCall(t *testing.T) {
	log := &orderLog{}
	f := newFake()
	p := New(&loggingClient{fakeClient: f, log: log})
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, *ServerInfo, string, provider.ProvisionOpts, func(string, string)) error {
		log.add("C:health")
		return nil
	})
	j := newRecJournal(log)
	opts := liveOpts()
	opts.WaitForHealth = true
	opts.Journal = j
	if _, err := p.Provision(context.Background(), opts); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertJournalOrder(t, log.lines)
	if len(j.begins) != 1 || j.begins[0] != provider.ModeCreate {
		t.Fatalf("begin modes = %v, want [create]", j.begins)
	}
	// The begin comes before anything is created.
	for _, l := range log.lines {
		if _, isCreate := createCalls[l]; isCreate {
			t.Fatalf("a create (%s) happened before begin", l)
		}
		if l == "J:begin:create" {
			break
		}
	}
	for _, kind := range []string{provider.KindSSHKey, provider.KindServer, provider.KindFirewall} {
		if len(j.created[kind]) != 1 {
			t.Errorf("created[%s] = %v, want exactly one", kind, j.created[kind])
		}
	}
	if len(j.deleted[provider.KindSSHKey]) != 1 {
		t.Errorf("the one-shot key's deletion was not journalled: %v", j.deleted)
	}
}

func TestProvisionJournal_FailedIntentStopsBeforeTheCreate(t *testing.T) {
	log := &orderLog{}
	f := newFake()
	p := New(&loggingClient{fakeClient: f, log: log})
	j := newRecJournal(log)
	j.failIntent = provider.KindServer
	opts := liveOpts()
	opts.Journal = j
	_, err := p.Provision(context.Background(), opts)
	if code, _ := provider.ProvisionErrorCode(err); code != provider.CodeJournalError {
		t.Fatalf("err = %v (code %q), want journal_error", err, code)
	}
	for _, l := range log.lines {
		if l == "C:ServerCreate" {
			t.Fatal("ServerCreate ran although its intent could not be journalled")
		}
	}
	if len(f.servers) != 0 {
		t.Fatalf("%d server(s) created", len(f.servers))
	}
}

// seedStranded plants what a killed setup leaves: a labelled server
// with the derived name and its one-shot key (whose defer never ran).
func seedStranded(t *testing.T, f *fakeClient, opts provider.ProvisionOpts, labelled bool) *ServerInfo {
	t.Helper()
	name := derivedServerName(opts.PublisherPubKey, opts.Region)
	labels := map[string]string{}
	if labelled {
		labels = map[string]string{labelManagedBy: labelManagedByValue, labelRelay: name}
	}
	srv, err := f.ServerCreate(context.Background(), ServerCreateOpts{Name: name, ServerType: "cx22", Region: "fsn1", Labels: labels})
	if err != nil {
		t.Fatal(err)
	}
	f.seedSSHKey(name+"-ephemeral-deadbeef", map[string]string{labelManagedBy: labelManagedByValue, labelRelay: name})
	return srv
}

func TestProvision_AdoptsAStrandedLabelledServerByRebuildingIt(t *testing.T) {
	log := &orderLog{}
	f := newFake()
	opts := liveOpts()
	stranded := seedStranded(t, f, opts, true)
	log.lines = nil
	p := New(&loggingClient{fakeClient: f, log: log})
	j := newRecJournal(log)
	opts.ExistingServerID = stranded.ID
	opts.Journal = j
	rec, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if rec.ServerID != stranded.ID {
		t.Fatalf("record names server %s, want the stranded %s", rec.ServerID, stranded.ID)
	}
	for _, l := range log.lines {
		if l == "C:ServerCreate" {
			t.Fatal("a second server was rented instead of finishing on the existing one")
		}
	}
	if !contains(log.lines, "C:ServerRebuild") {
		t.Fatalf("no rebuild: %v", log.lines)
	}
	if len(f.servers) != 1 {
		t.Fatalf("%d servers on the account, want 1", len(f.servers))
	}
	if len(j.begins) != 1 || j.begins[0] != provider.ModeAdopt {
		t.Fatalf("begin = %v, want adopt", j.begins)
	}
	if rec.MgmtPort < provider.MinMgmtPort {
		t.Fatalf("adopt produced no management port: %d", rec.MgmtPort)
	}
	// The killed run's key is gone, and so is this run's.
	if len(f.sshKeys) != 0 {
		t.Fatalf("%d ssh key(s) left on the account", len(f.sshKeys))
	}
	if len(j.deleted[provider.KindSSHKey]) != 2 {
		t.Fatalf("deleted ssh keys journalled = %v, want the stale one and this run's", j.deleted[provider.KindSSHKey])
	}
	assertJournalOrder(t, log.lines)
}

func TestProvision_RefusesAServerItCannotAdopt(t *testing.T) {
	cases := []struct {
		name     string
		labelled bool
		id       func(*ServerInfo) string
	}{
		{"labelled but no id given", true, func(*ServerInfo) string { return "" }},
		{"labelled but a different id", true, func(*ServerInfo) string { return "999" }},
		{"matching id but no labels", false, func(s *ServerInfo) string { return s.ID }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			opts := liveOpts()
			stranded := seedStranded(t, f, opts, tc.labelled)
			p := New(f)
			opts.ExistingServerID = tc.id(stranded)
			_, err := p.Provision(context.Background(), opts)
			code, sid := provider.ProvisionErrorCode(err)
			if code != provider.CodeServerExists || sid != stranded.ID {
				t.Fatalf("err = %v, code=%q server=%q; want server_exists naming %s", err, code, sid, stranded.ID)
			}
			if len(f.servers) != 1 {
				t.Fatalf("%d servers after a refusal, want 1", len(f.servers))
			}
			if f.lastUserData != "" {
				t.Fatal("the existing server was re-imaged although it could not be adopted")
			}
		})
	}
}

func TestProvision_RollbackOnAdoptDeletesTheProvenServer(t *testing.T) {
	f := newFake()
	opts := liveOpts()
	stranded := seedStranded(t, f, opts, true)
	p := New(f)
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, *ServerInfo, string, provider.ProvisionOpts, func(string, string)) error {
		return errors.New("hetzner: health check timed out after 60 attempts")
	})
	j := newRecJournal(&orderLog{})
	opts.ExistingServerID = stranded.ID
	opts.WaitForHealth = true
	opts.RollbackOnFailure = true
	opts.Journal = j
	_, err := p.Provision(context.Background(), opts)
	if code, _ := provider.ProvisionErrorCode(err); code != provider.CodeHealthTimeout {
		t.Fatalf("err = %v code %q, want health_timeout", err, code)
	}
	if len(f.servers) != 0 {
		t.Fatal("rollback on an adopted (proven-ours) server left it billing")
	}
	if len(j.deleted[provider.KindServer]) != 1 || j.deleted[provider.KindServer][0] != stranded.ID {
		t.Fatalf("server deletion not journalled: %v", j.deleted)
	}
}

// Opsec: neither the cloud token nor the per-run health token may ever
// reach the journal file.
func TestProvisionJournal_FileCarriesNoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	opts := liveOpts()
	jf, err := provjournal.Open(path, provjournal.Static{Provider: "hetzner", Region: "fsn1", ServerType: "cx22",
		ToolboxProfile: "iran-default", PublisherPubKey: opts.PublisherPubKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newFake()
	p := New(f)
	var healthToken string
	p.setHealthWaiter(func(_ context.Context, rec *provider.OperatorRecord, _ *ServerInfo, tok string, _ provider.ProvisionOpts, _ func(string, string)) error {
		healthToken = tok
		rec.MgmtTLSFingerprint = strings.Repeat("ab", 32)
		return nil
	})
	opts.WaitForHealth = true
	opts.Journal = jf
	rec, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := jf.Done(rec); err != nil {
		t.Fatal(err)
	}
	jf.Close()
	body, _ := os.ReadFile(path)
	if healthToken == "" || !strings.Contains(f.lastUserData, healthToken) {
		t.Fatal("test setup: the health token was not captured")
	}
	if strings.Contains(string(body), healthToken) {
		t.Fatal("the journal contains the provisioning health token")
	}
	for _, ev := range []string{`"ev":"begin"`, `"ev":"intent"`, `"ev":"created"`, `"ev":"done"`} {
		if !strings.Contains(string(body), ev) {
			t.Errorf("journal lacks %s:\n%s", ev, body)
		}
	}
}
