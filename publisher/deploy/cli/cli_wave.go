// Publisher-alone wave (contract D2, D3): users-renew and relay-health.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"daal/publisher/deploy/health"
	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayports"
)

// renewList is a repeatable flag that appends to one shared, ordered
// list, so --ensure/--replace/--revoke are handled in argv order.
type renewList struct {
	action string
	into   *[]mgmt.RenewRequest
}

func (r renewList) String() string { return "" }
func (r renewList) Set(v string) error {
	*r.into = append(*r.into, mgmt.RenewRequest{Name: v, Action: r.action})
	return nil
}

// runUsersRenew: daal-deploy users-renew --record-file F --priv-key - \
//
//	--helper-ip IP --token-file T [--ensure rN]... [--replace rN]...
//	[--revoke rN]... [--progress-json]
//
// stdout: {"users_before":[...],"results":[{name,action,ok,error_code,
// error,creds}]}. Exit 0 whenever the roster was read (per-name failures
// are in the JSON), 1 when nothing could be done, 2 usage, 3 relay too
// old to list its people. Credentials appear on stdout only.
func runUsersRenew(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("users-renew", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist)")
	tokenFile := fs.String("token-file", "", "cloud-provider API token file")
	progressJSON := fs.Bool("progress-json", false, "one JSON line per person on stderr (never carries credentials)")
	var reqs []mgmt.RenewRequest
	fs.Var(renewList{mgmt.RenewEnsure, &reqs}, "ensure", "keep rN if the relay has them, add them if not (REPEATABLE)")
	fs.Var(renewList{mgmt.RenewReplace, &reqs}, "replace", "give rN fresh credentials whether or not the relay has them (REPEATABLE)")
	fs.Var(renewList{mgmt.RenewRevoke, &reqs}, "revoke", "make sure the relay does not have rN (REPEATABLE)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--priv-key":    *privKeyFlag,
		"--helper-ip":   *helperIP,
		"--token-file":  *tokenFile,
	}); err != nil {
		return 2
	}
	if err := mgmt.ValidateRenewRequests(reqs); err != nil {
		fmt.Fprintf(stderr, "users-renew: %v\n", err)
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	priv, err := readPrivKey(*privKeyFlag, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "read priv-key: %v\n", err)
		return 1
	}
	defer zeroBytes(priv)
	prov, err := buildProviderFn(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	rep, err := mgmt.RenewUsersWithFW(ctx, prov, rec, priv, *helperIP, reqs, func(name, status string) {
		emitProgress(*progressJSON, stderr, "renew_user", "", map[string]any{"name": name, "status": status})
	})
	if err != nil {
		fmt.Fprintf(stderr, "users-renew: %v\n", err)
		if errors.Is(err, mgmt.ErrRelayRosterTooOld) {
			return 3
		}
		return 1
	}
	for _, r := range rep.Results {
		if r.Creds == nil {
			continue
		}
		for _, f := range mgmt.MissingFamilyCredentials(rec, r.Creds) {
			fmt.Fprintf(stderr, "warning: %s: this relay offers %q but reported no credential for it — %s\n",
				r.Name, f, mgmt.StaleArtifactHint)
		}
	}
	if err := json.NewEncoder(stdout).Encode(rep); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}

// HealthServer is the server leg of a relay-health report.
type HealthServer struct {
	State string `json:"state"` // running|stopped|starting|missing|not_checked|error
	Error string `json:"error"`
}

// HealthReport is relay-health's stdout (contract D3).
type HealthReport struct {
	V          int                `json:"v"`
	CheckedAt  string             `json:"checked_at"`
	Server     HealthServer       `json:"server"`
	Management *mgmt.MgmtHealth   `json:"management"`
	Ways       []health.WayResult `json:"ways"`
	Limits     []string           `json:"limits"`
}

// Honest limits, always stated.
const (
	LimitInsideCountryUnknown = "inside_country_unknown"
	LimitUDPNotTested         = "udp_not_tested"
)

// healthProbeWays is a test seam.
var healthProbeWays = health.ProbeWays

// runRelayHealth: daal-deploy relay-health --record-file F --priv-key - \
//
//	--helper-ip IP [--token-file T] [--timeout 8s]
//
// Read-only apart from the usual temporary firewall rule. Exit 0 whenever
// a report was produced, 1 for a bad record or key, 2 usage.
func runRelayHealth(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("relay-health", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist)")
	tokenFile := fs.String("token-file", "", "cloud-provider API token file (without it the server and management legs are not checked)")
	timeout := fs.Duration("timeout", 8*time.Second, "per-probe timeout")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	req := map[string]string{"--record-file": *recordFile, "--priv-key": *privKeyFlag}
	if *tokenFile != "" {
		req["--helper-ip"] = *helperIP
	}
	if err := requireAll(stderr, req); err != nil {
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	priv, err := readPrivKey(*privKeyFlag, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "read priv-key: %v\n", err)
		return 1
	}
	defer zeroBytes(priv)

	rep := HealthReport{
		V:          1,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		Server:     HealthServer{State: "not_checked"},
		Management: &mgmt.MgmtHealth{State: mgmt.MgmtNotChecked},
		Ways:       []health.WayResult{},
		Limits:     []string{LimitInsideCountryUnknown},
	}

	if *tokenFile != "" {
		prov, perr := buildProviderFn(rec.Provider, *tokenFile, false)
		if perr != nil {
			rep.Server = HealthServer{State: "error", Error: perr.Error()}
			rep.Management = &mgmt.MgmtHealth{State: mgmt.MgmtError, Error: perr.Error()}
		} else {
			if st, ok := prov.(provider.ServerStater); ok {
				sctx, cancel := context.WithTimeout(ctx, 2**timeout)
				state, serr := st.ServerState(sctx, rec)
				cancel()
				if serr != nil {
					rep.Server = HealthServer{State: "error", Error: serr.Error()}
				} else {
					rep.Server = HealthServer{State: state}
				}
			}
			switch rep.Server.State {
			case provider.ServerMissing, provider.ServerStopped:
				// Nothing can answer; opening a firewall rule for a
				// server that is gone or off would only fail.
				rep.Management = &mgmt.MgmtHealth{State: mgmt.MgmtNotChecked, Error: "the server is " + rep.Server.State}
			default:
				mctx, cancel := context.WithTimeout(ctx, 6**timeout)
				rep.Management = mgmt.HealthWithFW(mctx, prov, rec, priv, *helperIP, *timeout)
				cancel()
			}
		}
	}

	ways, anyUDP := healthWays(rec, rep.Management.Identity)
	coverSNI, pin := rec.CoverSNI, rec.TLSCertSHA256
	if id := rep.Management.Identity; id != nil {
		if id.CoverSNI != "" {
			coverSNI = id.CoverSNI
		}
		if id.TLSCertSHA256 != "" {
			pin = id.TLSCertSHA256
		}
	}
	rep.Ways = healthProbeWays(ctx, rec.PublicIP, ways, health.WayProbeOpts{CoverSNI: coverSNI, CertPin: pin, Timeout: *timeout})
	if anyUDP {
		rep.Limits = append(rep.Limits, LimitUDPNotTested)
	}
	if err := json.NewEncoder(stdout).Encode(rep); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}

// healthWays lists the ways in to probe: the relay's own statement when
// it gave one, otherwise the record's direct candidates on their
// canonical ports.
func healthWays(rec *provider.OperatorRecord, id *mgmt.RelayIdentity) ([]health.Way, bool) {
	var out []health.Way
	seen := map[string]bool{}
	anyUDP := false
	add := func(family string, port int) {
		if family == "" || seen[family] {
			return
		}
		seen[family] = true
		ep := relayports.For(family)
		if port <= 0 {
			port = ep.Port
		}
		if ep.UDP {
			anyUDP = true
		}
		out = append(out, health.Way{Family: family, Port: port, UDP: ep.UDP})
	}
	if id != nil && len(id.Families) > 0 {
		for _, f := range id.Families {
			add(f.Family, f.Port)
		}
		return out, anyUDP
	}
	for _, c := range rec.Candidates {
		if c.ExposureMode != "" && c.ExposureMode != "direct_vps" {
			continue // reached through a CDN, not at the relay's address
		}
		add(c.Family, 0)
	}
	return out, anyUDP
}
