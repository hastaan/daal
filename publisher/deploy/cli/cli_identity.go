// daal-deploy relay-identity — ask the relay who it is.
//
// The publisher signs a pack whose every route is committed to a signed
// endpoint (specs/relaypack-v1.md "Endpoint commitment"), and it signs
// BEFORE the first recipient exists. This verb fetches the relay's side
// of that commitment — REALITY public key, TLS key pin, cover host,
// shadowsocks server-key digest, served families and ports — from the
// relay's own management service (GET /identity,
// specs/daal-relay-mgmt-v1.md §4.9), on every provider, with no SSH and
// no recipient. Its output is what `bind-and-sign --relay-identity`
// reads.
//
// Conventions are the users-* ones: --record-file, --priv-key,
// --helper-ip, --token-file; the cloud firewall opens for the call and
// closes after it on every path; JSON on stdout.
//
// EXIT CODES
//
//	0  the relay's identity is on stdout (and in --output, if given)
//	1  failed (network, firewall, a relay that refused the token, a
//	   reply this publisher cannot read) — retrying may help
//	2  bad flags
//	3  the relay's software predates GET /identity. Not transient: the
//	   caller falls back to the older sources (the record, a
//	   users-provision reply via bind-and-sign --endpoint-creds).
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
)

// relayIdentityFn is the box call, replaceable in tests the same way
// the address verbs are (l3BindAddress): production always leaves it
// pointing at mgmt.IdentityWithFW.
var relayIdentityFn = mgmt.IdentityWithFW

func runRelayIdentity(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("relay-identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist)")
	tokenFile := fs.String("token-file", "", "cloud-provider API token file")
	outFile := fs.String("output", "", "also write the identity JSON here (mode 0600), for bind-and-sign --relay-identity")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--priv-key":    *privKeyFlag,
		"--helper-ip":   *helperIP,
	}); err != nil {
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
	id, err := relayIdentityFn(ctx, prov, rec, priv, *helperIP)
	if err != nil {
		fmt.Fprintf(stderr, "relay-identity: %v\n", err)
		if errors.Is(err, mgmt.ErrIdentityUnsupported) {
			return exitCapabilityUnsupported
		}
		return 1
	}
	body, err := json.Marshal(id)
	if err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, body, 0o600); err != nil {
			fmt.Fprintf(stderr, "write output: %v\n", err)
			return 1
		}
	}
	// Said on STDERR (stdout is the JSON): a pack signed from this
	// identity will be one route short, and why.
	for _, f := range id.PendingFamilies {
		fmt.Fprintf(stderr,
			"relay-identity: note: the relay serves %q but cannot identify it yet "+
				"(its key is made together with the first recipient); sign again after adding one\n", f)
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

// readRelayIdentityFile loads an identity saved by `relay-identity
// --output` (or by the wizard, which keeps the last one it fetched).
func readRelayIdentityFile(path string) (*mgmt.RelayIdentity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return mgmt.ParseRelayIdentity(raw)
}

// identityDisagreements lists where the relay's own identity and the
// OperatorRecord say different things. The relay's word is what gets
// signed (relaypack.EndpointMaterial.PreferRelay); these lines are so a
// disagreement is never silent, because each one means a recorded value
// went stale somewhere.
func identityDisagreements(rec *provider.OperatorRecord, id *mgmt.RelayIdentity) []string {
	out := []string{}
	if rec == nil || id == nil {
		return out
	}
	differ := func(a, b string) bool {
		a, b = strings.TrimSpace(a), strings.TrimSpace(b)
		return a != "" && b != "" && a != b
	}
	if differ(rec.CoverSNI, id.CoverSNI) {
		out = append(out, fmt.Sprintf("the record says the cover host is %s, the relay says %s; signing the relay's", rec.CoverSNI, id.CoverSNI))
	}
	if differ(rec.RealityPublicKey, id.RealityPublicKey) {
		out = append(out, "the record's REALITY public key is not the one the relay holds; signing the relay's")
	}
	if differ(rec.TLSCertSHA256, id.TLSCertSHA256) {
		out = append(out, "the record's TLS key pin is not the one the relay serves; signing the relay's")
	}
	// Ports are the record's to state (a CDN-fronted route is dialled on
	// the front's port, not the box's), so a mismatch on a direct route
	// is reported and NOT corrected.
	for _, c := range rec.Candidates {
		if c.ExposureMode == "cdn_fronted" {
			continue
		}
		if p := id.PortFor(c.Family); p != 0 && c.Port != 0 && p != c.Port {
			out = append(out, fmt.Sprintf("the record has %s on port %d, the relay serves it on %d", c.Family, c.Port, p))
		}
	}
	return out
}

// relayIdentityFreshFor is how long a relay identity is taken at its
// word about the COVER HOST when the record disagrees. It only has to
// cover "asked, then signed"; the management token window (300 s)
// already bounds how far the two clocks can be apart.
const relayIdentityFreshFor = 15 * 60 // seconds

// staleCoverHost reports whether id is too old to outrank the record on
// the cover host. See the call site in runBindAndSign.
func staleCoverHost(rec *provider.OperatorRecord, id *mgmt.RelayIdentity, ageSeconds int64) bool {
	if rec == nil || id == nil {
		return false
	}
	a, b := strings.TrimSpace(rec.CoverSNI), strings.TrimSpace(id.CoverSNI)
	if a == "" || b == "" || a == b {
		return false
	}
	return ageSeconds > relayIdentityFreshFor || ageSeconds < -relayIdentityFreshFor
}
