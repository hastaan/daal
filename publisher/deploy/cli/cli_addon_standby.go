package cli

// Add-on 1, standby address (docs/optional-addons-plan.md §1, item S5;
// specs/optional-addons-v1.md §3 and §6.3).
//
//	standby price   --token-file (--region R | --record-file F)
//	                    the monthly price of one Floating IPv4 in the relay's location
//	standby add     --record-file --token-file --priv-key --helper-ip [--mode sealed|open]
//	                    rent (or adopt what a killed run rented), assign without
//	                    adopting, bind on the box, check the mgmt pin and the data
//	                    port over it; rolls back on any failure
//	standby promote --record-file --token-file
//	                    the standby becomes the advertised address (record only)
//	standby remove  --record-file --token-file --priv-key --helper-ip [--skip-unbind]
//	                    unbind on the box, then release every standby of this relay
//	                    the record does not advertise; the caller has already
//	                    signed and published a pack without it
//
// Output: one JSON object on stdout (the updated record is inside it;
// --record-file is read, never written). It carries the standby key,
// which in sealed mode is the address: the wizard wipes stdout. With
// --progress-json, one JSON line per step on stderr.
//
// THE MONEY RULE. Hetzner bills a Floating IP per hour until it is
// deleted, assigned or not. So:
//   - a failed add releases what it rented or adopted, after telling the
//     box to drop it if the box was asked to bind it — and keeps it (and
//     says so, with the id) only when the box could not be told, because
//     handing an address back to the pool while a live box claims it is
//     worse than paying for it;
//   - a killed add leaves a Floating IP labelled daal-role=standby for
//     this relay, and the next add adopts it instead of renting another
//     (hetzner.EnsureStandby), the next remove releases it, and relay
//     delete releases it with the relay's other addresses;
//   - every run sweeps standbys an earlier killed run left (strays).

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"

	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/providers/hetzner"
	"daal/publisher/deploy/relaypack"
	"daal/publisher/deploy/rotation"
)

// exitStandbyLimit: the hosting company refused another Floating IP on
// this account (GATE S-1). Nothing is billing. First stderr line starts
// with "E_STANDBY_LIMIT:".
const exitStandbyLimit = 9

// standbyProvider is the provider surface the verbs need. Only the
// Hetzner adapter has it; any other answers "not supported".
type standbyProvider interface {
	EnsureStandby(ctx context.Context, rec *provider.OperatorRecord) (*hetzner.StandbyResult, error)
	PromoteStandby(ctx context.Context, rec *provider.OperatorRecord) (string, net.IP, error)
	RemoveStandby(ctx context.Context, rec *provider.OperatorRecord, fipID string) (bool, error)
	StandbyStrays(ctx context.Context, rec *provider.OperatorRecord) ([]provider.StandbyAddress, error)
	StandbyMonthlyPrice(ctx context.Context, region string) (hetzner.StandbyPrice, error)
}

var _ standbyProvider = (*hetzner.Provider)(nil)

// buildStandbyPriceFn builds the provider for `standby price`, which has
// no record to name one. A seam for tests, like buildProviderFn.
var buildStandbyPriceFn = func(tokenFile string) (standbyProvider, error) {
	p, err := buildProvider("hetzner", tokenFile, false)
	if err != nil {
		return nil, err
	}
	sp, ok := p.(standbyProvider)
	if !ok {
		return nil, errors.New("this hosting company has no standby address")
	}
	return sp, nil
}

func runStandby(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: daal-deploy standby price|add|promote|remove [flags]")
		return 2
	}
	switch args[0] {
	case "price":
		return runStandbyPrice(ctx, args[1:], stdout, stderr)
	case "add":
		return runStandbyAdd(ctx, args[1:], stdin, stdout, stderr)
	case "promote":
		return runStandbyPromote(ctx, args[1:], stdout, stderr)
	case "remove":
		return runStandbyRemove(ctx, args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown standby verb %q (want price|add|promote|remove)\n", args[0])
		return 2
	}
}

// standbyPriceOut is `standby price`'s answer, and the `price` member
// of `standby add`'s.
type standbyPriceOut struct {
	hetzner.StandbyPrice
	// Cents, rounded half up from the decimal strings. -1 when the
	// string could not be read.
	MonthlyNetCents   int64 `json:"monthly_net_cents"`
	MonthlyGrossCents int64 `json:"monthly_gross_cents"`
}

func priceOut(p hetzner.StandbyPrice) standbyPriceOut {
	return standbyPriceOut{StandbyPrice: p, MonthlyNetCents: decimalCents(p.MonthlyNet), MonthlyGrossCents: decimalCents(p.MonthlyGross)}
}

// decimalCents turns Hetzner's "3.0000000000" into 300. -1 if unreadable.
func decimalCents(s string) int64 {
	r, ok := new(big.Rat).SetString(strings.TrimSpace(s))
	if !ok || r.Sign() < 0 {
		return -1
	}
	r.Mul(r, big.NewRat(100, 1))
	r.Add(r, big.NewRat(1, 2))
	q := new(big.Int).Quo(r.Num(), r.Denom())
	if !q.IsInt64() {
		return -1
	}
	return q.Int64()
}

func runStandbyPrice(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("standby price", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	region := fs.String("region", "", "the relay's location (fsn1, nbg1, hel1, …)")
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path; its region is used when --region is empty")
	_ = fs.Bool("progress-json", false, "accepted for symmetry with the other verbs; price has no steps")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--token-file": *tokenFile}); err != nil {
		return 2
	}
	loc := strings.TrimSpace(*region)
	if loc == "" && *recordFile != "" {
		rec, err := readRecord(*recordFile)
		if err != nil {
			fmt.Fprintf(stderr, "read record-file: %v\n", err)
			return 1
		}
		if rec.Provider != "" && rec.Provider != "hetzner" {
			fmt.Fprintf(stderr, "standby price: the %s adapter has no standby address\n", rec.Provider)
			return 2
		}
		loc = rec.Region
	}
	if loc == "" {
		fmt.Fprintln(stderr, "standby price: pass --region or a --record-file that names one")
		return 2
	}
	sp, err := buildStandbyPriceFn(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	p, err := sp.StandbyMonthlyPrice(ctx, loc)
	if err != nil {
		fmt.Fprintf(stderr, "standby price: %v\n", err)
		return 1
	}
	return writeJSON(stdout, stderr, priceOut(p))
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	body, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(stderr, "marshal: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(append(body, '\n'))
	return 0
}

// standbyOut is the stdout of add, promote and remove.
type standbyOut struct {
	Record *provider.OperatorRecord `json:"record"`
	// FloatingIPID / Mode: the standby add made or found.
	FloatingIPID string `json:"floating_ip_id,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Created      bool   `json:"created,omitempty"`
	Adopted      bool   `json:"adopted,omitempty"`
	// Key is the standby key, text form (add, promote).
	Key   string           `json:"key,omitempty"`
	Price *standbyPriceOut `json:"price,omitempty"`
	// Promote: the address the relay moved off. When it was a Floating
	// IP it is still attached and billing.
	PriorFloatingIPID string `json:"prior_floating_ip_id,omitempty"`
	PriorAddress      string `json:"prior_address,omitempty"`
	// Released are Floating IP ids given back to the provider.
	Released []string `json:"released"`
	// StillBilling are Floating IPs this run meant to give back and
	// could not; each is still reserved and billing.
	StillBilling []standbyBilling `json:"still_billing"`
	Warnings     []string         `json:"warnings"`
}

type standbyBilling struct {
	FloatingIPID string `json:"floating_ip_id"`
	Address      string `json:"address,omitempty"`
	Reason       string `json:"reason"`
}

func newStandbyOut(rec *provider.OperatorRecord) *standbyOut {
	return &standbyOut{Record: rec, Released: []string{}, StillBilling: []standbyBilling{}, Warnings: []string{}}
}

// standbyEnv is what every mutating verb reads before touching anything.
type standbyEnv struct {
	rec      *provider.OperatorRecord
	p        providerFace
	sp       standbyProvider
	priv     ed25519.PrivateKey
	helperIP string
	progress bool
	stderr   io.Writer
}

func (e *standbyEnv) step(step, msg string, extra map[string]any) {
	emitProgress(e.progress, e.stderr, step, msg, extra)
}

// releaseStandby is the one way a standby goes back: unbind on the box
// (when the box may hold it), then release. An unbind that fails keeps
// the address — reserved and billing — rather than hand it to the pool
// while the box still answers on it.
func (e *standbyEnv) releaseStandby(ctx context.Context, out *standbyOut, sb provider.StandbyAddress, mayBeBound, skipUnbind bool) {
	if mayBeBound && !skipUnbind && len(sb.IP) > 0 {
		un, err := l3UnbindAddress(ctx, e.p, e.rec, e.priv, e.helperIP, e.rec.PublicIP, sb.IP)
		if un != nil {
			for _, w := range un.Warnings {
				out.Warnings = append(out.Warnings, w)
			}
		}
		if err != nil && !errors.Is(err, mgmt.ErrCapabilityUnsupported) {
			out.StillBilling = append(out.StillBilling, standbyBilling{FloatingIPID: sb.FloatingIPID, Address: ipString(sb.IP),
				Reason: "the relay could not be told to drop it (" + err.Error() + "); it stays reserved so no one else is handed an address this relay still answers on"})
			e.step("standby_still_billing", "kept: the relay could not be told to drop it", map[string]any{"floating_ip_id": sb.FloatingIPID})
			return
		}
	}
	deleted, err := e.sp.RemoveStandby(ctx, e.rec, sb.FloatingIPID)
	switch {
	case err != nil:
		out.StillBilling = append(out.StillBilling, standbyBilling{FloatingIPID: sb.FloatingIPID, Address: ipString(sb.IP), Reason: err.Error()})
		e.step("standby_still_billing", err.Error(), map[string]any{"floating_ip_id": sb.FloatingIPID})
	case !deleted:
		out.StillBilling = append(out.StillBilling, standbyBilling{FloatingIPID: sb.FloatingIPID, Address: ipString(sb.IP),
			Reason: "detached but not deleted: it does not carry Daal's labels for this relay"})
		e.step("standby_still_billing", "not Daal's to delete", map[string]any{"floating_ip_id": sb.FloatingIPID})
	default:
		out.Released = append(out.Released, sb.FloatingIPID)
		e.step("standby_released", "given back", map[string]any{"floating_ip_id": sb.FloatingIPID})
	}
}

func ipString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

// readStandbyEnv parses the shared flags of add and remove.
func readStandbyEnv(name string, args []string, stdin io.Reader, stderr io.Writer, needBox bool, extra func(*flag.FlagSet)) (*standbyEnv, int) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "this device's outbound public IP (firewall allowlist)")
	progress := fs.Bool("progress-json", false, "one JSON line per step on stderr")
	if extra != nil {
		extra(fs)
	}
	if rc := parseFlags(fs, args); rc >= 0 {
		return nil, rc
	}
	need := map[string]string{"--record-file": *recordFile, "--token-file": *tokenFile}
	if needBox {
		need["--priv-key"] = *privKeyFlag
		need["--helper-ip"] = *helperIP
	}
	if err := requireAll(stderr, need); err != nil {
		return nil, 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return nil, 1
	}
	env := &standbyEnv{rec: rec, helperIP: *helperIP, progress: *progress, stderr: stderr}
	if needBox {
		priv, err := readPrivKey(*privKeyFlag, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read priv-key: %v\n", err)
			return nil, 1
		}
		env.priv = priv
	}
	p, err := buildProviderFn(rec.Provider, *tokenFile, false)
	if err != nil {
		env.wipe()
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return nil, 1
	}
	sp, ok := p.(standbyProvider)
	if !ok {
		env.wipe()
		fmt.Fprintf(stderr, "%s: the %s adapter has no standby address\n", name, rec.Provider)
		return nil, 2
	}
	env.p, env.sp = p, sp
	return env, -1
}

func (e *standbyEnv) wipe() {
	if e != nil && e.priv != nil {
		zeroBytes(e.priv)
	}
}

func runStandbyAdd(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var mode *string
	env, rc := readStandbyEnv("standby add", args, stdin, stderr, true, func(fs *flag.FlagSet) {
		mode = fs.String("mode", provider.StandbySealed, "sealed (the pack carries a commitment) | open (the pack carries the address)")
	})
	if env == nil {
		return rc
	}
	defer env.wipe()
	rec := env.rec
	m := strings.TrimSpace(*mode)
	if m != provider.StandbySealed && m != provider.StandbyOpen {
		fmt.Fprintf(stderr, "standby add: --mode %q (want sealed or open)\n", m)
		return 2
	}
	// Refusals that cost nothing, before anything is rented.
	if !relaypack.StandbyEligibleRecord(rec) {
		fmt.Fprintln(stderr, "standby add: no route of this relay can use a standby address (shadowsocks and CDN routes cannot); nothing was rented")
		return 1
	}
	if len(rec.PublicIP) == 0 {
		fmt.Fprintln(stderr, "standby add: the record carries no current public IP, so the relay cannot be reached to bind the standby; nothing was rented")
		return 1
	}
	if rec.Standby != nil && rec.Standby.Mode != "" && rec.Standby.Mode != m {
		fmt.Fprintf(stderr, "standby add: this relay already has a %s standby; remove it before adding a %s one\n", rec.Standby.Mode, m)
		return 2
	}
	// STEP 0, as for assign-fip: a box that cannot bind an address can
	// never answer on a standby, so ask before renting one.
	caps, err := l3BoxCapabilities(ctx, env.p, rec, env.helperIP)
	if err != nil {
		fmt.Fprintf(stderr, "standby add: capability probe failed (nothing was rented): %v\n", err)
		return 1
	}
	if !caps.Has(mgmt.CapBindAddress) {
		fmt.Fprintf(stderr, "standby add: %v\n", mgmt.UnsupportedCapabilityError(caps, mgmt.CapBindAddress))
		return exitCapabilityUnsupported
	}

	out := newStandbyOut(rec)
	out.Mode = m
	if pr, err := env.sp.StandbyMonthlyPrice(ctx, rec.Region); err == nil {
		po := priceOut(pr)
		out.Price = &po
	}

	env.step("standby_renting", "renting a standby address", nil)
	res, err := env.sp.EnsureStandby(ctx, rec)
	if res != nil && res.Standby.FloatingIPID != "" {
		env.step("standby_created", "standby address in hand", map[string]any{
			"floating_ip_id": res.Standby.FloatingIPID, "created": res.Created, "adopted": res.Adopted})
	}
	// What this run is answerable for releasing if it fails: what it
	// rented or adopted. A standby the record already named belongs to
	// an earlier add that worked, and a failed repair does not bin it.
	ours := res != nil && res.Standby.FloatingIPID != "" && (res.Created || res.Adopted)
	bound := false
	fail := func(code int, format string, a ...any) int {
		if ours {
			env.releaseStandby(ctx, out, res.Standby, bound, false)
		}
		if res != nil {
			for _, s := range res.Strays {
				env.releaseStandby(ctx, out, s, true, false)
			}
		}
		out.Record = nil
		msg := fmt.Sprintf(format, a...)
		if len(out.StillBilling) > 0 {
			ids := make([]string, 0, len(out.StillBilling))
			for _, b := range out.StillBilling {
				ids = append(ids, b.FloatingIPID)
			}
			msg += fmt.Sprintf(" — and floating IP %s could NOT be given back: it is still reserved and billing; "+
				"`daal-deploy standby remove` releases it once the relay is reachable", strings.Join(ids, ", "))
		} else if ours {
			msg += " — the standby address was given back; nothing is billing"
		}
		fmt.Fprintln(stderr, msg)
		_ = writeJSON(stdout, stderr, out)
		return code
	}
	if err != nil {
		if errors.Is(err, hetzner.ErrStandbyLimit) {
			return fail(exitStandbyLimit, "E_STANDBY_LIMIT: Hetzner has not allowed this account a second address yet (%v)", err)
		}
		return fail(1, "standby add: %v", err)
	}
	out.FloatingIPID, out.Created, out.Adopted = res.Standby.FloatingIPID, res.Created, res.Adopted
	sbIP := res.Standby.IP

	// STEP 2: the box. Delivered over the address the relay answers on.
	env.step("standby_attaching", "binding the standby on the relay", nil)
	bound = true // from here the box may hold it, whatever the answer
	b, err := l3BindAddress(ctx, env.p, rec, env.priv, env.helperIP, rec.PublicIP, sbIP)
	if err != nil {
		code := 1
		if errors.Is(err, mgmt.ErrCapabilityUnsupported) {
			code = exitCapabilityUnsupported
		}
		return fail(code, "standby add: bind %s on the relay: %v", sbIP, err)
	}
	for _, w := range b.Warnings {
		out.Warnings = append(out.Warnings, w)
	}
	if !b.Persisted {
		return fail(1, "standby add: the relay bound %s but could not keep it across a reboot", sbIP)
	}

	// STEP 3: prove it from outside. The management certificate pin over
	// the standby says it is THIS box answering there, not merely
	// something; the data port says recipients would be answered.
	env.step("standby_checking", "checking the relay answers on the standby", nil)
	ctrl := *rec
	ctrl.PublicIP = append(net.IP(nil), sbIP...)
	if _, err := l3BoxCapabilities(ctx, env.p, &ctrl, env.helperIP); err != nil {
		return fail(1, "standby add: the relay's management key could not be checked over %s: %v", sbIP, err)
	}
	if err := l3AddressServes(sbIP, l3ProbePort, l3ProbeTimeout); err != nil {
		return fail(1, "standby add: %v", err)
	}

	salt := res.Standby.Salt
	if salt == "" {
		if salt, err = relaypack.NewStandbySalt(); err != nil {
			return fail(1, "standby add: draw salt: %v", err)
		}
	}
	rec.Standby = &provider.StandbyAddress{FloatingIPID: res.Standby.FloatingIPID, IP: sbIP, Mode: m, Salt: salt}
	if out.Key, err = relaypack.StandbyKeyText(rec.Standby); err != nil {
		rec.Standby = nil
		return fail(1, "standby add: %v", err)
	}
	// The pack must still sign with it; checked here so a record that
	// would make every later signature fail is never written.
	if _, err := relaypack.StandbyCommitmentFor(rec.Standby, ipString(rec.PublicIP)); err != nil {
		rec.Standby = nil
		return fail(1, "standby add: %v", err)
	}
	// Strays from earlier killed runs: billing for nothing.
	for _, s := range res.Strays {
		env.releaseStandby(ctx, out, s, true, false)
	}
	env.step("standby_ready", "standby ready", map[string]any{"floating_ip_id": res.Standby.FloatingIPID})
	return writeJSON(stdout, stderr, out)
}

func runStandbyPromote(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	env, rc := readStandbyEnv("standby promote", args, nil, stderr, false, nil)
	if env == nil {
		return rc
	}
	rec := env.rec
	if rec.Standby == nil {
		fmt.Fprintln(stderr, "standby promote: this relay has no standby address")
		return 2
	}
	key, err := relaypack.StandbyKeyText(rec.Standby)
	if err != nil {
		fmt.Fprintf(stderr, "standby promote: %v\n", err)
		return 1
	}
	sbIP := append(net.IP(nil), rec.Standby.IP...)
	// Never re-sign onto an address that does not answer. From the
	// publisher's side the standby is reachable even when recipients'
	// networks block the primary, so this is a real check.
	if err := l3AddressServes(sbIP, l3ProbePort, l3ProbeTimeout); err != nil {
		fmt.Fprintf(stderr, "standby promote: %v; nothing was changed\n", err)
		return 1
	}
	prior, priorIP, err := env.sp.PromoteStandby(ctx, rec)
	if err != nil {
		fmt.Fprintf(stderr, "standby promote: %v; nothing was changed\n", err)
		return 1
	}
	if err := rotation.CheckAddressMoved(priorIP, rec.PublicIP); err != nil {
		fmt.Fprintf(stderr, "standby promote: %v\n", err)
		return 1
	}
	if err := rotation.CheckRecordAddressConsistent(rec); err != nil {
		fmt.Fprintf(stderr, "standby promote: %v\n", err)
		return 1
	}
	out := newStandbyOut(rec)
	out.Key = key
	out.FloatingIPID = rec.FloatingIPID
	out.PriorFloatingIPID = prior
	out.PriorAddress = ipString(priorIP)
	if prior != "" {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"floating IP %s (%s), the address the relay moved off, is still attached and still billing; "+
				"release it with `daal-deploy floating-ip release --fip-id %s --fip-address %s` once the new pack has reached people",
			prior, priorIP, prior, priorIP))
	}
	return writeJSON(stdout, stderr, out)
}

func runStandbyRemove(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var skipUnbind *bool
	// --priv-key / --helper-ip are needed unless --skip-unbind; parse
	// first, then insist.
	pre := flag.NewFlagSet("", flag.ContinueOnError)
	pre.SetOutput(io.Discard)
	skipPre := pre.Bool("skip-unbind", false, "")
	_ = pre.Parse(filterFlag(args, "skip-unbind"))
	env, rc := readStandbyEnv("standby remove", args, stdin, stderr, !*skipPre, func(fs *flag.FlagSet) {
		skipUnbind = fs.Bool("skip-unbind", false,
			"release without telling the relay to drop the address; only for a relay that is gone or permanently unreachable")
	})
	if env == nil {
		return rc
	}
	defer env.wipe()
	rec := env.rec
	out := newStandbyOut(rec)

	var targets []provider.StandbyAddress
	if rec.Standby != nil {
		targets = append(targets, *rec.Standby)
	}
	strays, err := env.sp.StandbyStrays(ctx, rec)
	if err != nil {
		fmt.Fprintf(stderr, "standby remove: %v; nothing was released\n", err)
		_ = writeJSON(stdout, stderr, out)
		return 1
	}
	targets = append(targets, strays...)
	if *skipUnbind && len(targets) > 0 {
		out.Warnings = append(out.Warnings, "--skip-unbind: the relay was not told to drop the standby; if it is still alive it keeps answering on an address Hetzner may give to someone else")
	}
	for _, t := range targets {
		env.releaseStandby(ctx, out, t, true, *skipUnbind)
	}
	if len(out.StillBilling) > 0 {
		fmt.Fprintln(stderr, "standby remove: at least one standby address could not be given back and is still billing; run the same command again")
		_ = writeJSON(stdout, stderr, out)
		return exitAddressStillReserved
	}
	return writeJSON(stdout, stderr, out)
}

// filterFlag keeps only -name / --name / --name=v from args, so a
// pre-parse can read one flag without tripping on the others.
func filterFlag(args []string, name string) []string {
	var out []string
	for _, a := range args {
		t := strings.TrimLeft(a, "-")
		if t == name || strings.HasPrefix(t, name+"=") {
			out = append(out, a)
		}
	}
	return out
}
