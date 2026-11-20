package fieldprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"daal/bundle-go/fieldreport"
)

// Meta is what the report says about the device and the network,
// coarsely, beside what the run found.
type Meta struct {
	Platform     string
	NetKind      string // the host's kind: wifi | cellular | ethernet | other | ""
	Validated    int    // 1 | 0 | -1
	Metered      int
	IPv6Global   bool
	PrivateDNS   string
	Resolvers    []string // classed here, never copied
	NetworkLabel string
	Build        string
	Targets      *Targets
	Now          time.Time
	Notes        string
}

func tri(v int) string {
	switch v {
	case 1:
		return "yes"
	case 0:
		return "no"
	}
	return "unknown"
}

// BuildReport makes the schema-v2 report of a run. The result is
// validated before it is returned.
func BuildReport(res *Result, m Meta) (*fieldreport.Report, error) {
	id, err := fieldreport.NewReportID()
	if err != nil {
		return nil, err
	}
	kind, carrier := "unknown", "unknown"
	switch m.NetKind {
	case "wifi":
		kind, carrier = "wifi", "wifi"
	case "cellular":
		kind, carrier = "cellular", "mobile"
	case "ethernet":
		kind, carrier = "ethernet", "fixed"
	case "other":
		kind = "other"
	}
	label := m.NetworkLabel
	if !fieldreport.NetworkLabels[label] {
		label = "not_said"
	}
	country := "unknown"
	switch label {
	case "mci", "irancell", "rightel":
		country = "IR"
	}
	platform := m.Platform
	if !fieldreport.Platforms[platform] {
		platform = "unknown"
	}
	pdns := m.PrivateDNS
	if !fieldreport.PrivateDNS[pdns] {
		pdns = "unknown"
	}
	relayRef := "none"
	if res.RelayPackID != "" {
		sum := sha256.Sum256([]byte(res.RelayPackID))
		relayRef = hex.EncodeToString(sum[:4])
	}
	build := m.Build
	if build == "" {
		build = "unknown"
	}
	probes := make([]fieldreport.Probe, 0, len(res.Probes))
	for _, p := range res.Probes {
		probes = append(probes, p.Probe)
	}
	fs := Findings(res)
	r := &fieldreport.Report{
		SchemaVersion:       fieldreport.SchemaVersion,
		ReportID:            id,
		GeneratedHourBucket: m.Now.UTC().Truncate(time.Hour).Format("2006-01-02T15:00Z"),
		Platform:            platform,
		CountryHint:         country,
		CarrierClass:        carrier,
		NetworkLabel:        label,
		Net: fieldreport.Net{
			Kind: kind, Validated: tri(m.Validated), Metered: tri(m.Metered), IPv6Global: m.IPv6Global,
			PrivateDNS: pdns, ResolverClass: ResolverClass(ParseResolvers(m.Resolvers)),
		},
		App: fieldreport.App{
			Build: build, TargetsListVersion: m.Targets.Version, TargetsListSHA256: m.Targets.SHA256,
			DesyncAvailable: res.DesyncAvailable, HelloFP: res.HelloFP,
		},
		RelayRef: relayRef,
		Run: fieldreport.Run{
			Complete: res.Complete, AbortReason: res.AbortReason,
			DurationBucketS: fieldreport.DurationBucket(int(res.Elapsed / time.Second)),
			StepsRun:        res.StepsRun, ShortCircuit: res.ShortCircuit,
		},
		Probes:   probes,
		Findings: fs,
		Failures: Failures(res),
		Notes:    m.Notes,
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}
