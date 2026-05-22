package publisher

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"daal/bundle-go/bundle"
)

// VerifyOptions configures bundle verification.
type VerifyOptions struct {
	Path              string
	RequireTrustClass string
	MaxRouteCount     int
	RejectOnWarn      bool
}

// VerifyResult is the redacted summary returned to the operator.
type VerifyResult struct {
	OK              bool
	PublisherFPHex  string
	PublisherFPEN   string
	PublisherFPFA   string
	BundleID        string
	BundleExpiresAt string
	RouteCount      int
	RoutesByFamily  map[string]int
	LintFindings    []LintFinding
	Error           string
}

// Verify reads a .sbp from disk, validates it via bundle-go, and applies
// operator-mode policy flags.
func Verify(opts VerifyOptions) (*VerifyResult, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	body, err := os.ReadFile(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("read .sbp: %w", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return &VerifyResult{Error: err.Error()}, mapVerifyError(err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		return &VerifyResult{Error: err.Error()}, mapVerifyError(err)
	}
	if opts.RequireTrustClass != "" && parsed.Manifest.Publisher.TrustClass != opts.RequireTrustClass {
		return &VerifyResult{Error: fmt.Sprintf("trust_class %q does not satisfy --require-trust-class %q",
			parsed.Manifest.Publisher.TrustClass, opts.RequireTrustClass)}, ErrPolicyDenied
	}
	if opts.MaxRouteCount > 0 && len(parsed.Manifest.Routes) > opts.MaxRouteCount {
		return &VerifyResult{Error: "route count exceeds --max-route-count"}, ErrPolicyDenied
	}

	fp := bundle.PublisherFingerprint(parsed.PublisherPub)
	rendered, _ := bundle.RenderFingerprint(fp, defaultWordlists())
	families := map[string]int{}
	for _, r := range parsed.Manifest.Routes {
		families[r.TransportFamily]++
	}
	res := &VerifyResult{
		OK:              true,
		PublisherFPHex:  fp.Hex,
		PublisherFPEN:   rendered.EN,
		PublisherFPFA:   rendered.FA,
		BundleID:        parsed.Manifest.Bundle.ID,
		BundleExpiresAt: parsed.Manifest.Bundle.ExpiresAt,
		RouteCount:      len(parsed.Manifest.Routes),
		RoutesByFamily:  families,
	}

	if opts.RejectOnWarn {
		// Re-run lint engine for completeness; profile bytes are already in
		// parsed.Profiles.
		profiles := map[string][]byte{}
		for k, v := range parsed.Profiles {
			profiles[k] = v
		}
		res.LintFindings = LintRoutes(LintInput{
			Manifest: parsed.Manifest,
			Profiles: profiles,
		})
		for _, f := range res.LintFindings {
			if f.Level == LintWarn || f.Level == LintBlock {
				res.OK = false
				res.Error = fmt.Sprintf("lint finding %s: %s", f.Code, f.Reason)
				return res, ErrLintWarnings
			}
		}
	}
	return res, nil
}

// ErrPolicyDenied is returned when verify fails due to operator policy.
var ErrPolicyDenied = errors.New("policy denied")

// ErrLintWarnings is returned when verify fails due to --reject-on-warn.
var ErrLintWarnings = errors.New("lint warnings")

// mapVerifyError translates bundle-go errors into a stable category an
// operator can act on.
func mapVerifyError(err error) error {
	return fmt.Errorf("bundle invalid: %w", err)
}

// WriteRedactedSummary writes a small text summary to w. Private and
// signature material never appear here.
func WriteRedactedSummary(w io.Writer, r *VerifyResult) {
	if r == nil {
		return
	}
	fmt.Fprintln(w, "Publisher fingerprint:")
	fmt.Fprintf(w, "  hex: %s\n", r.PublisherFPHex)
	fmt.Fprintf(w, "   en: %s\n", r.PublisherFPEN)
	fmt.Fprintf(w, "   fa: %s\n", r.PublisherFPFA)
	fmt.Fprintf(w, "Bundle ID: %s\n", r.BundleID)
	fmt.Fprintf(w, "Expires:   %s\n", r.BundleExpiresAt)
	fmt.Fprintf(w, "Routes:    %d\n", r.RouteCount)
	for fam, n := range r.RoutesByFamily {
		fmt.Fprintf(w, "  %s: %d\n", fam, n)
	}
	if r.Error != "" {
		fmt.Fprintf(w, "Error: %s\n", r.Error)
	}
}
