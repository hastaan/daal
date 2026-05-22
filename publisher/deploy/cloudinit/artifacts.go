package cloudinit

// V1.5 pinned artefact manifest. The boot-time verifier shim
// (shim.sh.tmpl) downloads each artefact from the listed mirrors,
// verifies SHA-256 against `Sha256`, then verifies the Ed25519
// signature in `SigHex` against the embedded /etc/daal/release.pub.
//
// Updated by hand on each Daal release. The signing key for
// SigHex is the Daal release Ed25519 key whose public half is
// embedded as DaalReleasePubKeyPEM.
//
// FRP-4a placeholder values: at FRP-4a ship the artefact set is
// declared but the actual sha256/sig_hex values are dummies that
// the FRP-7 release pipeline will replace with real signed values.
// The shape is locked here so FRP-7's pipeline drop is a value
// edit, not a schema change.

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

// V15Artifacts is the V1.5 pinned set. Two artefacts at V1.5:
// sing-box (the relay engine) and daal-relay-health (the
// provisioning-window-only health endpoint).
//
// The Sha256 / SigHex fields here are placeholders ("FRP-4A-PLACEHOLDER...")
// that FRP-7's release pipeline replaces with real signed values
// before pilot. The shape and the mirrors list are LOCKED at FRP-4a;
// FRP-7 only edits the per-artefact sha256 + sig_hex.
var V15Artifacts = ArtifactManifest{
	Version: "v1.5.0",
	Artefacts: []Artifact{
		{
			Name:      "sing-box-1.10.0-linux-amd64",
			InstallAs: "sing-box",
			Sha256:    "FRP-4A-PLACEHOLDER-SHA256-FOR-SING-BOX-FRP7-WILL-FILL-THIS-IN",
			SigHex:    "FRP-4A-PLACEHOLDER-SIG-FOR-SING-BOX-FRP7-WILL-FILL-THIS-IN",
			Mirrors: []string{
				"https://mirror1.daal.invalid/v1.5/sing-box-1.10.0-linux-amd64",
				"https://mirror2.daal.invalid/v1.5/sing-box-1.10.0-linux-amd64",
			},
		},
		{
			Name:      "daal-relay-health-0.1.0-linux-amd64",
			InstallAs: "daal-relay-health",
			Sha256:    "FRP-4A-PLACEHOLDER-SHA256-FOR-HEALTH-FRP7-WILL-FILL-THIS-IN",
			SigHex:    "FRP-4A-PLACEHOLDER-SIG-FOR-HEALTH-FRP7-WILL-FILL-THIS-IN",
			Mirrors: []string{
				"https://mirror1.daal.invalid/v1.5/daal-relay-health-0.1.0-linux-amd64",
				"https://mirror2.daal.invalid/v1.5/daal-relay-health-0.1.0-linux-amd64",
			},
		},
	},
}

// DaalReleasePubKeyPEM is the Ed25519 public key the verifier shim
// uses to validate artefact signatures. FRP-7 replaces with the
// real production release key; FRP-4a ships a placeholder so the
// template renders cleanly.
const DaalReleasePubKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFRP4APLACEHOLDERPUBLICKEYFRP7WILLREPLACE0=
-----END PUBLIC KEY-----`
