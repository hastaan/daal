package cloudinit

// Pinned artefact manifests. The boot-time verifier shim
// (shim.sh.tmpl) downloads each artefact from the listed mirrors,
// verifies SHA-256 against `Sha256`, then verifies the Ed25519
// signature in `SigHex` against the embedded /etc/daal/release.pub.
//
// Updated by tools/release/relay-v1.5.0.sh on each Daal relay
// release. The signing key for SigHex is the Daal release Ed25519
// key whose public half is embedded as DaalReleasePubKeyPEM.

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
			Sha256:    "b7169ac97b20cbddf255d2f0ddfab5a5e7c57be9f003a505934969f7ab3be8fc",
			SigHex:    "eedaa2b38084589f5132f3ac217fa2b186655dca3c0352e7525c2b4a84b180d83aed5f9c04b57978b7c5639654ee61ea9ef714d7b8d22694eda7d2d60f29d60b",
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
			Sha256:    "b7169ac97b20cbddf255d2f0ddfab5a5e7c57be9f003a505934969f7ab3be8fc",
			SigHex:    "eedaa2b38084589f5132f3ac217fa2b186655dca3c0352e7525c2b4a84b180d83aed5f9c04b57978b7c5639654ee61ea9ef714d7b8d22694eda7d2d60f29d60b",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0/daal-relay-health-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0-mirror/daal-relay-health-0.1.0-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-mgmt-0.1.0-linux-amd64",
			InstallAs: "daal-relay-mgmt",
			Sha256:    "419fbddd6b234dad536f19599b3d09e2f701428fd08ca8e0947097264ab6dcac",
			SigHex:    "9a1e50af379956021d6f563e560d63916a49a06c9736fe3cb4fb44e32f6cdf7e0c27ac825a6a056d4e320a6454cf458b615473c8c51195077d10908670d1d804",
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
