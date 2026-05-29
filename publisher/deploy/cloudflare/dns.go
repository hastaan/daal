package cloudflare

import (
	"context"
	"errors"
)

// DNSPostureCheck holds the structured outcome of the deploy-time
// DNS check (per §11.7). The wizard surfaces dns_only_present into
// the signed CDNAttestation; the validator rejects bundles whose
// attestation reports DNSOnlyPresent=true (RP023).
type DNSPostureCheck struct {
	// DNSOnlyPresent is true if any non-proxied A or AAAA
	// record exists on the chosen subdomain. The wizard
	// refuses to deploy in this case, but the structured
	// flag is also signed into the CDN attestation so the
	// validator can independently reject the bundle later.
	DNSOnlyPresent bool

	// ProxiedRecordsEnsured is true if the wizard
	// successfully created/updated proxied A + AAAA records.
	ProxiedRecordsEnsured bool

	// Notes carries human-readable detail for the wizard's
	// posture panel.
	Notes string
}

// CheckAndEnsureDNS runs the §11.7 DNS posture check + record
// ensure pass, in order:
//
//  1. Call CFClient.EnsureProxiedRecords. The CFClient impl
//     (live or mock) is responsible for inspecting current
//     records and refusing to proceed if any non-proxied
//     A/AAAA exists. ErrDNSOnlyRecordPresent is returned in
//     that case.
//  2. On ErrDNSOnlyRecordPresent: return DNSOnlyPresent=true so
//     the wizard surfaces a clear error. The signed attestation
//     uses this flag.
//  3. On success: return ProxiedRecordsEnsured=true.
//
// Any other CF error propagates unwrapped (network failure, auth
// failure, etc.) so the wizard can retry.
func CheckAndEnsureDNS(
	ctx context.Context,
	cf CFClient,
	cfToken []byte,
	zoneID, hostname, originIPv4, originIPv6 string,
) (DNSPostureCheck, error) {
	if zoneID == "" || hostname == "" || originIPv4 == "" {
		return DNSPostureCheck{}, errors.New("dns: zoneID, hostname, originIPv4 required")
	}
	err := cf.EnsureProxiedRecords(ctx, cfToken, zoneID, hostname, originIPv4, originIPv6)
	switch {
	case err == nil:
		return DNSPostureCheck{
			DNSOnlyPresent:        false,
			ProxiedRecordsEnsured: true,
			Notes:                 "proxied A" + ifv6(originIPv6, " + AAAA") + " ensured",
		}, nil
	case errors.Is(err, ErrDNSOnlyRecordPresent):
		return DNSPostureCheck{
			DNSOnlyPresent: true,
			Notes:          "existing DNS-only A/AAAA record on " + hostname + " — refused per §11.7",
		}, err
	default:
		return DNSPostureCheck{}, err
	}
}

func ifv6(ipv6, suffix string) string {
	if ipv6 == "" {
		return ""
	}
	return suffix
}
