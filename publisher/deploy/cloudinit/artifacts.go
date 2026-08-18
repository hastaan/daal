package cloudinit

// Pinned artefact manifests. The boot-time verifier shim
// (shim.sh.tmpl) downloads each artefact from the listed mirrors,
// verifies SHA-256 against `Sha256`, then verifies the Ed25519
// signature in `SigHex` against the embedded /etc/daal/release.pub.
//
// Updated by tools/release/relay-v1.5.0.sh on each Daal relay
// release. The signing key for SigHex is the Daal release Ed25519
// key whose public half is embedded as DaalReleasePubKeyPEM.
//
// RELEASE COUPLING — read before changing cmd/daal-relay-mgmt.
//
// The publisher's own binary (daal-deploy) is rebuilt from source on
// every change; the BOX's binaries are pinned here by hash and only
// change when somebody rebuilds, re-signs and re-releases them. So any
// feature whose two halves live on opposite sides of that line is live
// on one side and absent on the other for as long as the pin is stale,
// and nothing in the build detects it. Two currently outstanding:
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
// When re-releasing, bump BOTH Sha256 and SigHex for
// daal-relay-mgmt-*, and re-run the provisioner-vs-client cross-check
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
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0/sing-box-1.13.12-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0-mirror/sing-box-1.13.12-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-health-0.1.0-linux-amd64",
			InstallAs: "daal-relay-health",
			Sha256:    "2afc4c5bdfd88b75736c6b7673b33367f04ad769a67f23c5ed386bb1651ac01c",
			SigHex:    "0a2b095d9dd81d63f4459b5cf69217e760de4a93970241cfd58625e59665c82b762349124a65764b1da94a78295d7c1da96efef8c623a064f81315646031430a",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0/daal-relay-health-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0-mirror/daal-relay-health-0.1.0-linux-amd64",
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
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0/sing-box-1.13.12-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0-mirror/sing-box-1.13.12-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-health-0.1.0-linux-amd64",
			InstallAs: "daal-relay-health",
			Sha256:    "2afc4c5bdfd88b75736c6b7673b33367f04ad769a67f23c5ed386bb1651ac01c",
			SigHex:    "0a2b095d9dd81d63f4459b5cf69217e760de4a93970241cfd58625e59665c82b762349124a65764b1da94a78295d7c1da96efef8c623a064f81315646031430a",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0/daal-relay-health-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0-mirror/daal-relay-health-0.1.0-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-mgmt-0.1.0-linux-amd64",
			InstallAs: "daal-relay-mgmt",
			Sha256:    "e8cb16e8ef021dd60d5d7aee60bd4b93e495e571d3d514a0b75c0695765df66b",
			SigHex:    "de2e6fe16590aab97934831f8fbb6fbfdaf8dc0d293fe804a2049b61c295014c9db93d74a1d63cbcbf76988227008a90e7ce262f10220d1b8f230ce8155c1806",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0/daal-relay-mgmt-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0-mirror/daal-relay-mgmt-0.1.0-linux-amd64",
			},
		},
	},
}

// DaalReleasePubKeyPEM is the Ed25519 public key the verifier shim
// uses to validate artefact signatures.
const DaalReleasePubKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEATGVDyH8Gzd+qu2HYpmw/nfwgKNxXm27DEpaQZDAz2W8=
-----END PUBLIC KEY-----`
