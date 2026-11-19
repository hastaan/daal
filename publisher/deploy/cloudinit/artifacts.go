package cloudinit

// Pinned artefact manifests. The boot-time verifier shim
// (shim.sh.tmpl) downloads each artefact from the listed mirrors,
// verifies SHA-256 against `Sha256`, then verifies the Ed25519
// signature in `SigHex` against the embedded /etc/daal/release.pub.
//
// Updated from the snippet tools/release/relay-v1.5.1.sh stages, on
// each Daal relay release — as ONE commit with everything
// tools/release/README.md ("The pin bump") lists. The signing key for SigHex is the Daal release Ed25519
// key whose public half is embedded as DaalReleasePubKeyPEM.
//
// RELEASE COUPLING — read before changing cmd/daal-relay-mgmt.
//
// The publisher's own binary (daal-deploy) is rebuilt from source on
// every change; the BOX's binaries are pinned here by hash and only
// change when somebody rebuilds, re-signs and re-releases them. So any
// feature whose two halves live on opposite sides of that line is live
// on one side and absent on the other for as long as the pin is stale,
// and nothing in the build detects it. The couplings so far (none is
// outstanding since the 2026-11-19 pin, relay-v1.5.1):
//
//   - COVER SNI (Wave 2 Step 4). RESOLVED 2026-08-17: the pin below was
//     bumped to an artefact built from this tree, so a freshly provisioned
//     box echoes its own cover host on /users/provision. The record
//     fallback (`users-pack-sbp[x] --cover-sni`) remains as defence in
//     depth for boxes provisioned before this release — a raw CLI
//     invocation against such a box still needs the flag.
//
//   - IN-PLACE ROTATION (Wave 3 Step 7). RESOLVED 2026-08-18: the pin
//     below now carries the scoped `/rotate-credentials`, the key-free
//     `/rotate-tls`, the `/health` capability advertisement, the
//     rollback-on-failed-reload and the mutex serializing the mutating
//     routes. Relays provisioned before this pin still run the
//     pre-Step-7 handler and still fail CLOSED: the publisher probes
//     `/health` first (mgmt/capability.go) and refuses with
//     E_RELAY_TOO_OLD before sending a mutating byte, because the old
//     handler ignores `name`, rotates every recipient and re-keys the
//     box. Such a relay cannot be upgraded in place — provision a new
//     one.
//
//   - ADDRESS BINDING (Wave 3c). RESOLVED 2026-08-18, but with a
//     COUPLING THIS FILE ALONE CANNOT CARRY. `/bind-address` needs
//     CAP_NET_ADMIN, which is granted by `AmbientCapabilities` in
//     v2.yaml.tmpl — a unit file written once, at first boot. So this
//     feature is gated on the cloud-init template as well as on the
//     hash below, and a relay handed only the new binary correctly
//     reports `bind-address` unavailable (probeAddressBinding reads the
//     effective capability set from /proc/self/status rather than
//     assuming how it was started). L3 therefore requires a relay
//     provisioned FRESH from this tree; there is no upgrade path.
//
//   - MULTIPLEX (Wave 2 Step 5). Fails safe by construction: the
//     capability travels box→publisher (`mux_inbound`), so an
//     un-updated box reports nothing, the pack emits no mux block, and
//     the route works exactly as before — it just gets none of the
//     benefit until the artefact ships.
//
//   - OPT-IN FAMILIES (Wave 5: shadowsocks, anytls, tuic). RESOLVED
//     2026-11-19 (finding F-002): the pin below serves them. Unlike
//     multiplex this does NOT fail safe on its own: the operator-facing
//     half (the wizard's "More ways to connect", `provision --families`)
//     lives on the publisher's side and would offer them regardless of
//     the pin. It is gated by PinnedMgmtServesOptInFamilies, below the
//     manifests, which was false until this pin.
//
//   - MGMT TOKEN v2 (finding REL-1). RESOLVED 2026-11-19, AND IT DOES
//     NOT FAIL SAFE. The publisher in this tree signs the request into
//     every management token (mgmt.MintToken, format v2) and the daemon
//     built from this tree refuses anything else. The previous pin
//     (relay-v1.5.0) was a v1 daemon: a relay provisioned with it
//     booted, passed health, and answered 401 to the first
//     users-provision. There is deliberately no fallback to v1 in
//     either direction, so the pin and the publisher move together.
//
//   - AUTHENTICATED BOOTSTRAP (daal-relay-health; finding BOOT-1).
//     RESOLVED 2026-11-19, FAILS CLOSED. The publisher in this tree
//     pins a management-TLS fingerprint only when the health reply
//     authenticates it with the provisioning secret, and asks for it
//     under a path token derived from that secret
//     (publisher/deploy/health/bootstrap.go, spec
//     daal-relay-mgmt-v1.md §2.1). The daal-relay-health of
//     relay-v1.5.0 predates both: it answers the derived path with 404,
//     and Provision stops with health.ErrBootstrapRefused about ten
//     seconds after the box comes up. No fallback, for the reason MGMT
//     TOKEN v2 has none. So daal-relay-health is coupled to this tree
//     exactly as daal-relay-mgmt is: any change under
//     publisher/deploy/health or cmd/daal-relay-health means the
//     release script runs again.
//
//   - RELAY-V1.5.1. 2026-11-19: the pin below moved to relay-v1.5.1,
//     built from this tree. It carries token v2 (bound to method, path,
//     body digest and relay), the authenticated bootstrap (BOOT-1),
//     GET /identity, the opt-in families on the box (F-002), single-use
//     tokens, the naive ALPN key (INT-2), the single reload, and the
//     certificate re-issue on rotate-tls. A publisher from this tree
//     cannot manage a relay-v1.5.0 box, and that is deliberate: there
//     is no upgrade path and no downgrade — provision a new one.
//
// When re-releasing, bump BOTH Sha256 and SigHex for
// daal-relay-mgmt-* AND daal-relay-health-*, flip PinnedMgmtServesOptInFamilies (and its TS
// mirror) in the same commit, and re-run the provisioner-vs-client
// cross-check
// (publisher/deploy/providers/hetzner/cover_sni_singbox_test.go).

// Artifact is one pinned binary the box fetches and installs.
type Artifact struct {
	Name      string   `json:"name"`       // versioned release name (e.g. "sing-box-1.10.0-linux-amd64")
	InstallAs string   `json:"install_as"` // final basename in /usr/local/bin/ (e.g. "sing-box")
	Sha256    string   `json:"sha256"`     // hex; lowercase
	SigHex    string   `json:"sig_hex"`    // Ed25519 signature over the binary, hex
	Mirrors   []string `json:"mirrors"`    // tried in order; first verified wins
}

// ArtifactManifest is the JSON shape written to /etc/daal/artifacts.json.
type ArtifactManifest struct {
	Version   string     `json:"version"`
	Artefacts []Artifact `json:"artefacts"`
}

var V15Artifacts = ArtifactManifest{
	Version: "v1.5.0",
	Artefacts: []Artifact{
		{
			Name:      "sing-box-1.13.12-linux-amd64",
			InstallAs: "sing-box",
			Sha256:    "989e848637725005fdac7f1d3fa3d6eeb16992c5e0a68789da96b6b3fde06ea2",
			SigHex:    "ff5ba04d6dddee1bd3350cccb828f366efc6f95d5b73ea98f49679001a45be543810fbfeb3c9d0737b12e0dd3fb050c48b7d629278d74bd0f9e4a4a1630eb10a",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1/sing-box-1.13.12-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1-mirror/sing-box-1.13.12-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-health-0.1.0-linux-amd64",
			InstallAs: "daal-relay-health",
			Sha256:    "407581d6b583d5d55f477b473087ed6e6cab65e6b9b88a0ba8eb1b196a76d055",
			SigHex:    "deb98a9a8f855a0e3975544923586a7952f822fb6999d679d08fc9da8f08998355e56d8023827b6986d91df6ad2a561dfb034eab375d97190da63b1ec4bd1300",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1/daal-relay-health-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1-mirror/daal-relay-health-0.1.0-linux-amd64",
			},
		},
	},
}

var V2Artifacts = ArtifactManifest{
	Version: "v2.0.0",
	Artefacts: []Artifact{
		{
			Name:      "sing-box-1.13.12-linux-amd64",
			InstallAs: "sing-box",
			Sha256:    "989e848637725005fdac7f1d3fa3d6eeb16992c5e0a68789da96b6b3fde06ea2",
			SigHex:    "ff5ba04d6dddee1bd3350cccb828f366efc6f95d5b73ea98f49679001a45be543810fbfeb3c9d0737b12e0dd3fb050c48b7d629278d74bd0f9e4a4a1630eb10a",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1/sing-box-1.13.12-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1-mirror/sing-box-1.13.12-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-health-0.1.0-linux-amd64",
			InstallAs: "daal-relay-health",
			Sha256:    "407581d6b583d5d55f477b473087ed6e6cab65e6b9b88a0ba8eb1b196a76d055",
			SigHex:    "deb98a9a8f855a0e3975544923586a7952f822fb6999d679d08fc9da8f08998355e56d8023827b6986d91df6ad2a561dfb034eab375d97190da63b1ec4bd1300",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1/daal-relay-health-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1-mirror/daal-relay-health-0.1.0-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-mgmt-0.1.0-linux-amd64",
			InstallAs: "daal-relay-mgmt",
			Sha256:    "4f13e4538e5299c35ecd648c48754790d3859fac6b03695aecda42354e61f9de",
			SigHex:    "884b0d52f9b91a14920b7e6b0138b04926ab4087b98441bba33a72555bf2b47562c6969896dc857af4ba544bed747a07346b5c1ee8689bcfa0a8a6c1baceab09",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1/daal-relay-mgmt-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.1-mirror/daal-relay-mgmt-0.1.0-linux-amd64",
			},
		},
	},
}

// PinnedMgmtServesOptInFamilies says whether the daal-relay-mgmt pinned
// in V2Artifacts above — the ONLY mgmt daemon an app- or CLI-provisioned
// relay ever downloads — serves the opt-in families in
// OptInFamiliesOfMgmt (finding F-002).
//
// It is false today. The pinned 0.1.0 artefact (Sha256 e8cb16e8…) was
// built before those families landed in cmd/daal-relay-mgmt: it creates
// no `ss-in` / `anytls-in`, returns no `ss_password` / `anytls_password`
// / `tuic_uuid`, and so a relay asked for one of them gets no such
// route in any connection file — while a signed manifest that names
// anytls still stamps the file spec_version 5, which older apps refuse
// whole. All of the cost, none of the benefit.
//
// Everything that OFFERS these families to an operator reads this one
// constant instead of promising them:
//
//   - the build wizard's "More ways to connect" switches are shown but
//     cannot be ticked, with the reason (client-ui/src/publisher
//     /extraFamilies.ts mirrors this value; tools/check-toolbox-profiles
//     .mjs and extraFamilies.test.tsx fail when the two disagree);
//   - `daal-deploy provision --families …` says "will be ASKED to
//     serve" and names what the release cannot serve yet
//     (publisher/deploy/cli/cli_families.go).
//
// FLIP IT TO true IN THE SAME COMMIT THAT BUMPS Sha256/SigHex of
// daal-relay-mgmt-* to an artefact built from a tree that has
// cmd/daal-relay-mgmt/families.go, and set the TS mirror with it.
// TestPinnedMgmtOptInGateMatchesThePin fails on a bump that forgets to,
// and on a flip without a bump. The acceptance test for the flip is the
// rig world `release.all-families` (`./run.sh clean`, pinned) going
// green.
const PinnedMgmtServesOptInFamilies = true

// mgmtPinBeforeOptInFamilies is the SHA-256 of the last released
// daal-relay-mgmt that predates the opt-in families. While the pin
// equals it, PinnedMgmtServesOptInFamilies must be false.
const mgmtPinBeforeOptInFamilies = "e8cb16e8ef021dd60d5d7aee60bd4b93e495e571d3d514a0b75c0695765df66b"

// OptInFamiliesOfMgmt are the families whose relay half lives in
// daal-relay-mgmt and landed after the artefact named by
// mgmtPinBeforeOptInFamilies. In serving order of iran-default.
var OptInFamiliesOfMgmt = []string{"shadowsocks", "anytls", "tuic"}

// NotServedByPinnedMgmt returns, in the order given, the families of
// the list that a relay provisioned from this build would be asked to
// serve but whose pinned mgmt daemon cannot. Nil when the pin serves
// everything asked.
func NotServedByPinnedMgmt(families []string) []string {
	return notServedBy(PinnedMgmtServesOptInFamilies, families)
}

func notServedBy(servesOptIn bool, families []string) []string {
	if servesOptIn {
		return nil
	}
	var out []string
	for _, f := range families {
		for _, o := range OptInFamiliesOfMgmt {
			if f == o {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// DaalReleasePubKeyPEM is the Ed25519 public key the verifier shim
// uses to validate artefact signatures.
const DaalReleasePubKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEATGVDyH8Gzd+qu2HYpmw/nfwgKNxXm27DEpaQZDAz2W8=
-----END PUBLIC KEY-----`
