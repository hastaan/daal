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
			Sha256:    "4d17143b721273ae3e220f8f720b34ce3f5fc1235a12763930a616ae0dce68e1",
			SigHex:    "fb50f8f22364f9772a5201a6e2f5e03999ae489894e7a43c103a78f67c9c2c8ab748e5e2f31cd697cf453af6763256987425834e09428ad7ec78b768e9608d0e",
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
			Sha256:    "4d17143b721273ae3e220f8f720b34ce3f5fc1235a12763930a616ae0dce68e1",
			SigHex:    "fb50f8f22364f9772a5201a6e2f5e03999ae489894e7a43c103a78f67c9c2c8ab748e5e2f31cd697cf453af6763256987425834e09428ad7ec78b768e9608d0e",
			Mirrors: []string{
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0/daal-relay-health-0.1.0-linux-amd64",
				"https://github.com/hastaan/daal/releases/download/relay-v1.5.0-mirror/daal-relay-health-0.1.0-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-mgmt-0.1.0-linux-amd64",
			InstallAs: "daal-relay-mgmt",
			Sha256:    "adab6e93d7fdec93ffc90953a2b40f5858638b133880f6108ac9d04366d315fd",
			SigHex:    "40648f9956ac5acdd0b16091973b166711e2ad8681f6ba6ed2a36ab2b9375614ff663fcac54fa835545964a2831cf8df2e1357b4a6d3fd609f78b8d6c99f2d0f",
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
