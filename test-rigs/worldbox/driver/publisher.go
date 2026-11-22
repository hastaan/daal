package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Publisher is the OUTSIDER: the person with the wizard. It owns a
// keypair and a working directory and does everything by running the
// REAL daal-deploy binary, unmodified, inside the publisher namespace —
// the same verbs with the same flags the Tauri shim passes.
//
// Two things stand in for the wizard itself and are the rig's, not the
// product's: generating the Ed25519 keypair (the wizard's keystore does
// that) and remembering file paths between verbs.
type Publisher struct {
	p     Paths
	Dir   string
	steps int

	// endpointCreds is the newest reply the relay gave to a
	// users-provision — the file the wizard would have saved. Its
	// relay-wide fields (REALITY public key, TLS pin, shadowsocks server
	// key) are what bind-and-sign commits each route's signed endpoint
	// to. This rig has no sshd, so the OperatorRecord carries none of
	// them (README "What is real and what is not"); on a VPS the record
	// has the first two and this file supplies the rest.
	endpointCreds string

	// identityFile is the relay's own statement of who it is, as
	// `relay-identity` last saved it — the file the wizard stages for
	// `bind-and-sign --relay-identity`. Empty until the relay has been
	// asked, and for a relay too old to answer; BindAndSign then falls
	// back to endpointCreds, as the app does.
	identityFile string
	// Committed is what the last bind-and-sign said the pack commits
	// the relay to (its `committed_identity`). The app keeps the same
	// thing, to notice when a later reply from the relay disagrees.
	Committed CommittedIdentity
}

// CommittedIdentity mirrors bind-and-sign's `committed_identity`.
type CommittedIdentity struct {
	Server            string   `json:"server"`
	CoverSNI          string   `json:"cover_sni"`
	RealityPublicKey  string   `json:"reality_public_key"`
	TLSCertSHA256     string   `json:"tls_cert_sha256"`
	SSMethod          string   `json:"ss_method"`
	SSServerKeySHA256 string   `json:"ss_server_key_sha256"`
	Families          []string `json:"families"`
}

// RelayIdentityDoc is the part of the relay's identity the rig reads.
type RelayIdentityDoc struct {
	RealityPublicKey  string   `json:"reality_public_key"`
	TLSCertSHA256     string   `json:"tls_cert_sha256"`
	CoverSNI          string   `json:"cover_sni"`
	SSServerKeySHA256 string   `json:"ss_server_key_sha256"`
	PendingFamilies   []string `json:"pending_families"`
}

// exitRelayCannotSay is `relay-identity`'s reserved exit code for a
// relay whose software predates the identity route.
const exitRelayCannotSay = 3

// ToolboxProfile is the profile every relay in the rig is provisioned with.
const ToolboxProfile = "iran-default"

// Verb is the outcome of one daal-deploy invocation.
type Verb struct {
	Argv   []string
	RC     int
	Stdout string
	Stderr string
	Ms     int64
}

func (v Verb) OK() bool { return v.RC == 0 }

// Tail is the end of stderr, for a check's detail line.
func (v Verb) Tail() string {
	s := strings.TrimSpace(v.Stderr)
	if len(s) > 1500 {
		s = "…" + s[len(s)-1500:]
	}
	return s
}

func NewPublisher(p Paths) (*Publisher, error) {
	dir := filepath.Join(p.Run, "publisher")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "publisher.pub"), pub, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "publisher.priv"), priv, 0o600); err != nil {
		return nil, err
	}
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	if err := os.WriteFile(filepath.Join(dir, "cloud.token"), []byte(fmt.Sprintf("%x\n", tok)), 0o600); err != nil {
		return nil, err
	}
	return &Publisher{p: p, Dir: dir}, nil
}

func (pb *Publisher) Path(name string) string { return filepath.Join(pb.Dir, name) }

// Deploy runs `daal-deploy <args>` as the publisher. The process sees the
// lab's /etc/hosts (api.hetzner.cloud → the lab) and the lab CA; nothing
// else about its environment differs from a laptop.
func (pb *Publisher) Deploy(ctx context.Context, args ...string) Verb {
	return pb.deployStdin(ctx, nil, args...)
}

func (pb *Publisher) deployStdin(ctx context.Context, stdin []byte, args ...string) Verb {
	pb.steps++
	script := `mount --bind "$WB_HOSTS" /etc/hosts && exec "$@"`
	argv := inNS(NSPublisher, "unshare", "--mount", "--propagation", "private", "sh", "-c", script, "sh",
		filepath.Join(pb.p.Bin, "daal-deploy"))
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = pb.Dir
	cmd.Env = append(os.Environ(), "WB_HOSTS="+pb.p.Hosts(), "SSL_CERT_FILE="+pb.p.CA())
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	t0 := time.Now()
	err := cmd.Run()
	v := Verb{Argv: append([]string{"daal-deploy"}, args...), Stdout: so.String(), Stderr: se.String(), Ms: time.Since(t0).Milliseconds()}
	if err != nil {
		v.RC = 1
		if ee, ok := err.(*exec.ExitError); ok {
			v.RC = ee.ExitCode()
		} else {
			v.Stderr += "\n[worldbox] " + err.Error()
		}
	}
	// Every verb, verbatim, in order: the publisher's side of the story.
	rec, _ := json.Marshal(map[string]any{"n": pb.steps, "argv": v.Argv, "rc": v.RC, "ms": v.Ms, "stdout": v.Stdout, "stderr": v.Stderr})
	if f, err := os.OpenFile(filepath.Join(pb.p.Run, "publisher-verbs.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		f.Write(append(rec, '\n'))
		f.Close()
	}
	return v
}

// ---- the verbs, with the flags the app passes ------------------------

func (pb *Publisher) Provision(ctx context.Context, families []string, extra ...string) Verb {
	args := []string{"provision", "--provider", "hetzner", "--region", "fsn1", "--server-type", "cx22",
		"--toolbox-profile", ToolboxProfile,
		"--pubkey-file", pb.Path("publisher.pub"), "--token-file", pb.Path("cloud.token"),
		"--helper-ip", PublisherIP, "--progress-json", "-o", pb.Path("record.json")}
	if len(families) > 0 {
		args = append(args, "--families", strings.Join(families, ","))
	}
	return pb.Deploy(ctx, append(args, extra...)...)
}

// BindAndSign signs the base pack against record.json as it is NOW.
// Every route is committed to an endpoint (address, port, the key that
// proves the relay is the relay), so it has to be run again after any
// rotation that moves one of those: users-pack-sbp refuses to mint from
// a signed pack that no longer describes the relay.
//
// It signs from what the app signs from: the relay's own identity when
// the relay has stated one (RelayIdentity), and otherwise the newest
// users-provision reply.
func (pb *Publisher) BindAndSign(ctx context.Context, out string, extra ...string) Verb {
	if pb.identityFile == "" {
		return pb.BindAndSignFor(ctx, out, pb.endpointCreds, extra...)
	}
	args := []string{"bind-and-sign", "--operator-record", pb.Path("record.json"),
		"--priv-key", pb.Path("publisher.priv"), "--output", pb.Path(out),
		"--publisher-name", "Worldbox Publisher",
		"--relay-identity", pb.Path(pb.identityFile)}
	v := pb.Deploy(ctx, append(args, extra...)...)
	pb.noteCommitted(v)
	return v
}

func (pb *Publisher) noteCommitted(v Verb) {
	if !v.OK() {
		return
	}
	var ans struct {
		Committed CommittedIdentity `json:"committed_identity"`
	}
	if json.Unmarshal([]byte(v.Stdout), &ans) == nil {
		pb.Committed = ans.Committed
	}
}

// RelayIdentity asks the relay who it is (mgmt GET /identity) and saves
// the answer where BindAndSign picks it up — the first thing the app
// does before every signature. Exit 3 means the relay's software
// predates the route; nothing is saved and the caller falls back.
func (pb *Publisher) RelayIdentity(ctx context.Context) (Verb, RelayIdentityDoc) {
	const file = "relay-identity.json"
	v := pb.Deploy(ctx, "relay-identity", "--record-file", pb.Path("record.json"),
		"--priv-key", pb.Path("publisher.priv"), "--token-file", pb.Path("cloud.token"),
		"--helper-ip", PublisherIP, "--output", pb.Path(file))
	var doc RelayIdentityDoc
	if v.OK() {
		pb.identityFile = file
		_ = json.Unmarshal([]byte(v.Stdout), &doc)
	}
	return v, doc
}

// BindAndSignFor is BindAndSign with an explicit relay reply to take
// the relay-wide connection material from.
func (pb *Publisher) BindAndSignFor(ctx context.Context, out, credsFile string, extra ...string) Verb {
	args := []string{"bind-and-sign", "--operator-record", pb.Path("record.json"),
		"--priv-key", pb.Path("publisher.priv"), "--output", pb.Path(out),
		"--publisher-name", "Worldbox Publisher"}
	if credsFile != "" {
		args = append(args, "--endpoint-creds", pb.Path(credsFile))
	}
	v := pb.Deploy(ctx, append(args, extra...)...)
	pb.noteCommitted(v)
	return v
}

// UsersProvision creates a recipient on the relay and saves the box's
// credential reply to creds-<name>.json, as the wizard does.
func (pb *Publisher) UsersProvision(ctx context.Context, name string) Verb {
	v := pb.Deploy(ctx, "users-provision", "--record-file", pb.Path("record.json"),
		"--priv-key", pb.Path("publisher.priv"), "--token-file", pb.Path("cloud.token"),
		"--helper-ip", PublisherIP, "--name", name)
	if v.OK() {
		_ = os.WriteFile(pb.Path("creds-"+name+".json"), []byte(v.Stdout), 0o600)
		pb.endpointCreds = "creds-" + name + ".json"
	}
	return v
}

func (pb *Publisher) UsersRevoke(ctx context.Context, name string) Verb {
	return pb.Deploy(ctx, "users-revoke", "--record-file", pb.Path("record.json"),
		"--priv-key", pb.Path("publisher.priv"), "--token-file", pb.Path("cloud.token"),
		"--helper-ip", PublisherIP, "--name", name)
}

func (pb *Publisher) UsersList(ctx context.Context) Verb {
	return pb.Deploy(ctx, "users-list", "--record-file", pb.Path("record.json"),
		"--priv-key", pb.Path("publisher.priv"), "--token-file", pb.Path("cloud.token"),
		"--helper-ip", PublisherIP)
}

// PackSBP turns the signed base pack + one recipient's credentials into
// the file that gets handed to an insider.
func (pb *Publisher) PackSBP(ctx context.Context, in, credsFile, out string, extra ...string) Verb {
	rec, _ := pb.Record()
	args := []string{"users-pack-sbp", "--in", pb.Path(in), "--out", pb.Path(out),
		"--creds-file", pb.Path(credsFile), "--server", rec.PublicIP}
	if rec.CoverSNI != "" {
		args = append(args, "--cover-sni", rec.CoverSNI)
	}
	return pb.Deploy(ctx, append(args, extra...)...)
}

// Record is the subset of OperatorRecord the rig reads. It never writes
// the record; the verbs own it.
type Record struct {
	Provider           string `json:"provider"`
	ServerID           string `json:"server_id"`
	PublicIP           string `json:"public_ip"`
	MgmtPort           int    `json:"mgmt_port"`
	MgmtTLSFingerprint string `json:"mgmt_tls_fingerprint"`
	CoverSNI           string `json:"cover_sni"`
	RealityPublicKey   string `json:"reality_public_key"`
	Candidates         []struct {
		Family string `json:"family"`
		Port   int    `json:"port"`
	} `json:"candidates"`
}

func (pb *Publisher) Record() (Record, error) {
	var r Record
	body, err := os.ReadFile(pb.Path("record.json"))
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(body, &r)
}
