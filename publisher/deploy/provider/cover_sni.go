package provider

import (
	"fmt"
	"time"

	"daal/publisher/deploy/sni"
)

// Cover-SNI resolution for provider adapters.
//
// These three functions are the only places a cover hostname is decided.
// They exist next to ResolveMgmtPort because they solve the same problem
// in the same shape: a per-relay value that must be chosen once, written
// to the OperatorRecord, and then honoured verbatim on every retry.
//
// The invariant every adapter must hold: whatever these return is
// stamped into BOTH the REALITY inbound's tls.server_name AND its
// reality.handshake.server in the cloud-init config, and onto
// OperatorRecord.CoverSNI. A relay whose advertised name and fallback
// dest disagree is the exact probe mismatch REALITY exists to prevent.

// ResolveCoverSNI decides the cover hostname for a relay that is about
// to be built (create, rebuild, or dry run).
//
//   - requested non-empty: the record already carries a cover host, so
//     reuse it verbatim. This is what keeps an idempotent retry from
//     moving a live box's SNI out from under already-distributed packs.
//   - requested empty: choose one from the pool, seeded by the relay's
//     durable identity so the same relay always lands on the same host.
//
// The one exception is deliberate: a record still carrying the legacy
// fleet-wide constant is upgraded rather than honoured. That value is a
// property of the *old* box; a box being built now must never be born
// with it, because it is the fleet-wide correlation Wave 2 removes.
func ResolveCoverSNI(requested, seed, region string) (string, error) {
	if requested != "" && requested != sni.LegacyCoverSNI {
		if err := sni.ValidHost(requested); err != nil {
			return "", err
		}
		return requested, nil
	}
	host := sni.Pick(seed, region)
	if host == "" {
		return "", fmt.Errorf("cover sni: pool has no admissible host for region %q", region)
	}
	return host, nil
}

// ReuseCoverSNI describes the cover host of a box that already exists
// and is being adopted rather than built — the idempotent
// "server already present, return its record" path.
//
// IT REFUSES TO GUESS, and the reason is worth stating because an
// earlier version did guess. The argument is opts.CoverSNI, i.e. the
// --cover-sni flag, NOT the record; nothing feeds the persisted value
// back automatically. So "empty" does not mean "this box predates the
// field", it means "the caller did not say", and a Wave-2 relay
// serving mirror.dogado.de would quietly acquire
// cover_sni:"www.cloudflare.com" in the operator's own source of
// truth. The consequences compound rather than stay cosmetic:
//
//   - the pack minter now prefers the record's value when the box's
//     mgmt binary is too old to echo one, so a wrong record is a dead
//     vless tier for every recipient, not a display bug;
//   - NextCoverSNI excludes rec.CoverSNI when rotating, so a wrong
//     record excludes the wrong host and rotation can hand a burned
//     relay straight back its burned name.
//
// This is the same call MgmtPort makes three lines up in every adapter,
// for the same reason: on the adopt path the operator is by
// construction working from a persisted record, so requiring them to
// pass what it says costs one flag and removes a whole failure class.
// A genuinely pre-Wave-2 record has no cover host to pass; those
// operators pass sni.LegacyCoverSNI explicitly, which is a claim
// somebody made rather than one the code invented.
func ReuseCoverSNI(persisted string) (string, error) {
	if persisted == "" {
		return "", fmt.Errorf(
			"existing server requires the persisted CoverSNI (pass --cover-sni "+
				"with the record's cover_sni; a record minted before Wave 2 has "+
				"none, and that box advertises %q)", sni.LegacyCoverSNI)
	}
	// The legacy constant is inadmissible by the rule and is accepted
	// here anyway, because this function DESCRIBES a box rather than
	// choosing for one: a pre-Wave-2 relay really is advertising it, and
	// refusing to say so would leave the operator no way to adopt their
	// own running relay. ResolveCoverSNI, which does choose, upgrades it.
	if persisted == sni.LegacyCoverSNI {
		return persisted, nil
	}
	if err := sni.ValidHost(persisted); err != nil {
		return "", err
	}
	return persisted, nil
}

// NextCoverSNI picks the cover host for a re-provision. Rotation must
// MOVE the value — re-provisioning a relay because its cover host was
// burned, and handing it back the same host, is not a rotation.
//
//   - requested non-empty (ReprovisionOpts.NewSNI, i.e. an explicit L2
//     rotation): honour it after validation.
//   - requested empty: pick a fresh host from the relay's zone,
//     excluding the one it is currently advertising. The seed carries
//     the rotation instant so successive rotations of the same relay
//     keep moving instead of oscillating between two hosts.
func NextCoverSNI(rec *OperatorRecord, requested string, now time.Time) (string, error) {
	if rec == nil {
		return "", fmt.Errorf("cover sni: nil OperatorRecord")
	}
	if requested != "" {
		if err := sni.ValidHost(requested); err != nil {
			return "", err
		}
		return requested, nil
	}
	seed := rec.ServerID + "@" + now.UTC().Format(time.RFC3339Nano)
	host := sni.PickExcluding(seed, rec.Region, rec.CoverSNI)
	if host == "" {
		return "", fmt.Errorf("cover sni: pool has no admissible host for region %q", rec.Region)
	}
	return host, nil
}
