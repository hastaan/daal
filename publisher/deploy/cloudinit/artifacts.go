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
//   - COVER SNI (Wave 2 Step 4). daal-deploy writes a per-relay cover
//     host into cloud-init today; the mgmt handler that echoes it back
//     on /users/provision is in the source tree and NOT in the pinned
//     artefact below. Mitigated, not fixed: the pack minter falls back
//     to OperatorRecord.CoverSNI (`users-pack-sbp[x] --cover-sni`, which
//     the wizard passes), so packs are correct even against an
//     un-updated box. A raw CLI invocation that omits the flag still
//     mints a pack advertising the legacy constant against a box serving
//     a pool host, which kills the vless tier silently.
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
			Sha256:    "704d2e7f9415186c8d498e9f9f7ca1de51a18c1e2a3445c95b2a8bdc37353705",
			SigHex:    "f77d9daafca95242c77fa2454283d6295195b68625956d2f4b7b19f59b32a41587ef1ad2c5b6130ae0766d1ab71653c345a21ee6e17bfb98a168c184a06a490c",
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
			Sha256:    "704d2e7f9415186c8d498e9f9f7ca1de51a18c1e2a3445c95b2a8bdc37353705",
			SigHex:    "f77d9daafca95242c77fa2454283d6295195b68625956d2f4b7b19f59b32a41587ef1ad2c5b6130ae0766d1ab71653c345a21ee6e17bfb98a168c184a06a490c",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0/daal-relay-health-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0-mirror/daal-relay-health-0.1.0-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-mgmt-0.1.0-linux-amd64",
			InstallAs: "daal-relay-mgmt",
			Sha256:    "7325b7231778dd2dcd514a784a4e31c31c124280f77af9adbc5d381941a6133a",
			SigHex:    "8389e27b565bbb49e30ace32de4554dab3d6a18cb77b7f8a336fc24ecfa80db5cbef6c01b21c4f51af382977a959806161a070cb60a1d193b077c87d381b5f07",
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
