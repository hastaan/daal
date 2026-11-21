package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Shared plumbing for the lifecycle ops (ops_recipients.go, ops_l1.go,
// ops_l2.go, ops_l3.go, ops_mgmtauth.go, ops_caps.go, ops_freshness.go):
// the things that happen to a relay AFTER first contact.
//
// Everything that changes the world here is a real daal-deploy verb with
// the flags the wizard passes (client-shell/tauri/daal-wizard/src/
// cli_bridge.rs). The helpers only remember file names between verbs.

// ---- verbs -----------------------------------------------------------

// mgmtFlags are the four flags every mgmt-plane verb takes.
func (pb *Publisher) mgmtFlags() []string {
	return []string{"--record-file", pb.Path("record.json"), "--priv-key", pb.Path("publisher.priv"),
		"--token-file", pb.Path("cloud.token"), "--helper-ip", PublisherIP}
}

// RotateCredentials is L1: re-mint ONE recipient's credentials on the
// box. The verb's stdout has the /users/provision shape; it is saved to
// credsOut exactly as the wizard persists it before doing anything else.
func (pb *Publisher) RotateCredentials(ctx context.Context, name, credsOut string) Verb {
	v := pb.Deploy(ctx, append([]string{"rotate-credentials", "--name", name}, pb.mgmtFlags()...)...)
	if v.OK() {
		_ = os.WriteFile(pb.Path(credsOut), []byte(v.Stdout), 0o600)
	}
	return v
}

// RotateTLS is L2: move the relay's cover identity. No --new-sni, as in
// the app: the publisher picks a fresh admissible host. The verb rewrites
// record.json in place.
func (pb *Publisher) RotateTLS(ctx context.Context, extra ...string) Verb {
	return pb.Deploy(ctx, append(append([]string{"rotate-tls"}, pb.mgmtFlags()...), extra...)...)
}

// AssignFIP is L3: reserve a fresh address, attach it, have the box bind
// it, probe it, and only then rewrite record.json.
func (pb *Publisher) AssignFIP(ctx context.Context, extra ...string) Verb {
	return pb.Deploy(ctx, append(append([]string{"assign-fip"}, pb.mgmtFlags()...), extra...)...)
}

// ReleaseFIP gives an address back: detach, have the box unbind it,
// release it. With no extra flags it releases the address the record is
// currently on, which puts the relay back on its primary address.
func (pb *Publisher) ReleaseFIP(ctx context.Context, extra ...string) Verb {
	return pb.Deploy(ctx, append(append([]string{"floating-ip", "release"}, pb.mgmtFlags()...), extra...)...)
}

// PackFor mints a pack from an explicit base pack + credentials file,
// against whatever record.json says now (server address, cover host).
func (pb *Publisher) PackFor(ctx context.Context, base, credsFile, out string) Verb {
	return pb.PackSBP(ctx, base, credsFile, out)
}

// ---- what the publisher holds ----------------------------------------

// Creds is one recipient's credential document, as the box returned it.
type Creds map[string]any

func (c Creds) Str(k string) string { s, _ := c[k].(string); return s }

func (pb *Publisher) ReadCreds(file string) (Creds, error) {
	body, err := os.ReadFile(pb.Path(file))
	if err != nil {
		return nil, err
	}
	var c Creds
	return c, json.Unmarshal(body, &c)
}

// perUserSecrets are the fields that must differ between two recipients
// and must change when one recipient is rotated. ss_password is
// "<box iPSK>:<recipient uPSK>"; only the recipient half is per-user, so
// it is compared through ssUserHalf.
var perUserSecrets = []string{"vless_uuid", "reality_short_id", "hy2_password", "naive_password",
	"tuic_uuid", "tuic_password", "anytls_password", "ss_password"}

// boxWideMaterial are the fields every recipient of one relay shares and
// that L1 must not move. ws_path is one of them: the relay has ONE ws-in
// inbound with one path, every recipient dials it, and recipients are
// told apart by UUID (the product says so in cli_rotate.go).
var boxWideMaterial = []string{"reality_public_key", "tls_cert_sha256", "cover_sni", "ss_method", "ws_path"}

func ssUserHalf(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func secretOf(c Creds, field string) string {
	if field == "ss_password" {
		return ssUserHalf(c.Str(field))
	}
	return c.Str(field)
}

// RecordMap is record.json, whole. The typed Record in publisher.go is
// the subset the matrix needs; lifecycle ops also read fields that only
// exist after a rotation (floating_ip_id).
func (pb *Publisher) RecordMap() map[string]any {
	body, err := os.ReadFile(pb.Path("record.json"))
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

// ---- what the box holds ----------------------------------------------

// BoxFile reads a file from the box's /etc as the product left it.
func (rc *RunCtx) BoxFile(rel string) (string, error) {
	body, err := os.ReadFile(filepath.Join(rc.P.Box(rc.Rec.ServerID), "etc-upper", rel))
	return string(body), err
}

// BoxSingboxConfig is the relay's live sing-box config.
func (rc *RunCtx) BoxSingboxConfig() string {
	s, _ := rc.BoxFile("sing-box/config.json")
	return s
}

// boxInbounds returns inbound tag → the user names it carries.
func (rc *RunCtx) boxInbounds() map[string][]string {
	var doc struct {
		Inbounds []struct {
			Tag   string           `json:"tag"`
			Users []map[string]any `json:"users"`
		} `json:"inbounds"`
	}
	_ = json.Unmarshal([]byte(rc.BoxSingboxConfig()), &doc)
	out := map[string][]string{}
	for _, in := range doc.Inbounds {
		names := []string{}
		for _, u := range in.Users {
			for _, k := range []string{"name", "username"} {
				if s, _ := u[k].(string); s != "" {
					names = append(names, s)
					break
				}
			}
		}
		sort.Strings(names)
		out[in.Tag] = names
	}
	return out
}

// relayAddrs lists the IPv4 addresses on the relay's public NIC.
func (rc *RunCtx) relayAddrs() []string {
	out, _ := sh(rc.Ctx, inNS(NSRelay1, "ip", "-4", "-o", "addr", "show", "dev", "eth0")...)
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i, tok := range f {
			if tok == "inet" && i+1 < len(f) {
				addrs = append(addrs, strings.SplitN(f[i+1], "/", 2)[0])
			}
		}
	}
	return addrs
}

// ---- the insider's seat, for something other than a full session ------

// tcpFromClient: can the insider's network complete a TCP handshake with
// ip:port? (The censor is in the path.)
func (rc *RunCtx) tcpFromClient(ip string, port int) bool { return rc.tcpFrom(NSClient, ip, port) }

// liveFamilies are the families a lifecycle op can learn anything from:
// under test, exercisable, and NOT blocked by the scenario. A family the
// censor blocks would be "blocked" before and after every operation, so
// its sessions prove nothing about the operation and only cost their
// timeouts; it gets one explicit skipped line per op instead.
func (rc *RunCtx) liveFamilies(phase string) []Family {
	var out []Family
	for _, f := range rc.activeFamilies() {
		if scn, _ := rc.Scn.ExpectFor(f.Name); scn == Blocked {
			rc.R.Add(f.Name, phase, "sessions", Skipped, Skipped,
				"scenario "+rc.Scn.Name+" blocks "+f.Name+": its sessions would be blocked whatever this op did", nil, time.Now())
			continue
		}
		out = append(out, f)
	}
	return out
}

// ---- the wizard's "Rebuild" ------------------------------------------

// Rebuild re-issues one recipient's file the way the app's Rebuild button
// does (recipient_book.rs recipient_repack_sbpx): best-effort revoke of
// the name, provision the same name again, sign `base` again if the
// reply says the relay moved (heal_after_reply: on a relay whose only
// recipient this is, the revoke dropped the shadowsocks server key and
// the provision minted another), pack against the current record. It
// returns the new pack. base is the signed base pack to rewrite
// ("base.sbp" unless the op re-signed one); every caller signs it with
// no extra flags, which is how the heal signs it again.
func (rc *RunCtx) Rebuild(name, phase, base, tag string) (string, bool) {
	t0 := time.Now()
	_ = rc.Pub.UsersRevoke(rc.Ctx, name) // best effort, as in the app
	v := rc.Pub.UsersProvision(rc.Ctx, name)
	if !rc.R.Add("", phase, "rebuild."+name+".users-provision", Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0) {
		return "", false
	}
	if !rc.healAfterReply(phase, name, base) {
		return "", false
	}
	out := "pack-" + name + "-" + tag + ".sbp"
	v = rc.Pub.PackSBP(rc.Ctx, base, "creds-"+name+".json", out)
	if !rc.R.Add("", phase, "rebuild."+name+".users-pack-sbp", Pass, got(v.OK() && !strings.Contains(v.Stderr, "NOT connectable"), Pass, Fail),
		v.Tail(), map[string]any{"stdout": strings.TrimSpace(v.Stdout)}, t0) {
		return "", false
	}
	return rc.Pub.Path(out), true
}

// ---- hand-built mgmt requests ----------------------------------------

// MgmtProbe sends hand-built requests to the relay's mgmt API from
// INSIDE the relay's own network namespace, over loopback.
//
// Why from there: the mgmt port is shut to the world by two firewalls
// and opened to one address for the duration of one verb. These checks
// are about what the API does once somebody IS talking to it, so the
// probe stands where both firewalls have already been passed (loopback
// is accepted by both). The firewalls themselves are asserted
// separately (provision/mgmt_port_closed_to_strangers,
// cloud.mgmt_window_closed).
func (rc *RunCtx) MgmtProbe(reqs []MgmtReq) (map[string]MgmtAns, error) {
	in, _ := json.Marshal(reqs)
	argv := inNS(NSRelay1, filepath.Join(rc.P.Bin, "wb"), "mgmtprobe",
		"--addr", fmt.Sprintf("127.0.0.1:%d", rc.Rec.MgmtPort), "--fpr", rc.Rec.MgmtTLSFingerprint,
		"--priv", rc.Pub.Path("publisher.priv"))
	cmd := exec.CommandContext(rc.Ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	runErr := cmd.Run()
	var answers []MgmtAns
	if err := json.Unmarshal(so.Bytes(), &answers); err != nil {
		return nil, fmt.Errorf("mgmtprobe: %v / %v: %s", runErr, err, strings.TrimSpace(se.String()))
	}
	out := map[string]MgmtAns{}
	for _, a := range answers {
		out[a.ID] = a
	}
	if f, err := os.OpenFile(filepath.Join(rc.P.Run, "mgmt-probes.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		for i, a := range answers {
			var q MgmtReq
			if i < len(reqs) {
				q = reqs[i]
			}
			line, _ := json.Marshal(map[string]any{"request": q, "answer": a})
			f.Write(append(line, '\n'))
		}
		f.Close()
	}
	if runErr != nil {
		return out, fmt.Errorf("mgmtprobe: %v: %s", runErr, strings.TrimSpace(se.String()))
	}
	return out, nil
}

// Health asks the relay's mgmt /health what it says it can do.
func (rc *RunCtx) Health() (caps []string, version int, raw string, err error) {
	ans, err := rc.MgmtProbe([]MgmtReq{{ID: "health", Method: "GET", Path: "/health"}})
	if err != nil {
		return nil, 0, "", err
	}
	h := ans["health"]
	if h.Status != 200 {
		return nil, 0, h.Body, fmt.Errorf("/health answered %d %s %s", h.Status, h.Body, h.Error)
	}
	var doc struct {
		Capabilities []string `json:"capabilities"`
		Version      int      `json:"mgmt_api_version"`
	}
	if err := json.Unmarshal([]byte(h.Body), &doc); err != nil {
		return nil, 0, h.Body, err
	}
	return doc.Capabilities, doc.Version, h.Body, nil
}

// ---- the whole lifecycle, in the order it happens to a real relay ------

// LifecycleOps is `--ops lifecycle`. The order matters: `caps` judges
// the relay's advertised capabilities against what the earlier ops
// observed, and `l2` invalidates every pack minted before it (which is
// its documented cost), so it goes last among the rotations.
var LifecycleOps = []string{"recipients", "revoke", "l1", "l3", "l2", "mgmtauth", "freshness", "caps"}

func init() {
	Ops["lifecycle"] = func(rc *RunCtx) {
		for _, name := range LifecycleOps {
			if op, ok := Ops[name]; ok {
				fmt.Fprintf(rc.R.human, "op: %s (lifecycle)\n", name)
				op(rc)
			}
		}
	}
}

// checksWhere returns the recorded checks matching keep — how one op
// reads what earlier ops in the same run observed.
func (r *Results) checksWhere(keep func(Check) bool) []Check {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Check
	for _, c := range r.all {
		if keep(c) {
			out = append(out, c)
		}
	}
	return out
}
