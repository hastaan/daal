// daal-publish is the operator-facing CLI for producing signed .sbp
// bundles, sub-keys, revocation lists, and root-key rotations.
//
// daal-publish never opens a network socket. All operations are local.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"daal/bundle-go/bundle"
	"daal/bundle-go/publisher"
)

const versionString = "daal-publish 0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		os.Exit(cmdKeygen(os.Args[2:]))
	case "subkey":
		os.Exit(cmdSubkey(os.Args[2:]))
	case "bundle":
		os.Exit(cmdBundle(os.Args[2:]))
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	case "revoke":
		os.Exit(cmdRevoke(os.Args[2:]))
	case "rotate-key":
		os.Exit(cmdRotateKey(os.Args[2:]))
	case "fingerprint":
		os.Exit(cmdFingerprint(os.Args[2:]))
	case "webtunnel-bridge":
		// Phase 3A. See specs/publisher-cli-v1.md and
		// specs/webtunnel-route-v1.md.
		os.Exit(cmdWebTunnelBridge(os.Args[2:]))
	case "snowflake-rendezvous-hint":
		// Phase 3B. See specs/publisher-cli-v1.md and
		// specs/snowflake-route-v1.md.
		os.Exit(cmdSnowflakeRendezvousHint(os.Args[2:]))
	case "masque-bridge":
		// Phase 3C. See specs/publisher-cli-v1.md and
		// specs/masque-ladder-v1.md.
		os.Exit(cmdMasqueBridge(os.Args[2:]))
	case "psiphon-bundle":
		// Phase 3D. See specs/publisher-cli-v1.md and
		// specs/psiphon-route-v1.md.
		os.Exit(cmdPsiphonBundle(os.Args[2:]))
	case "conjure-bridge":
		// Phase 3D. See specs/publisher-cli-v1.md and
		// specs/conjure-route-v1.md.
		os.Exit(cmdConjureBridge(os.Args[2:]))
	case "wasm-module":
		// Phase 3E. See specs/publisher-cli-v1.md and
		// specs/wasm-transport-v1.md.
		os.Exit(cmdWasmModule(os.Args[2:]))
	case "wasm-killswitch":
		// Phase 3E. See specs/publisher-cli-v1.md and
		// specs/wasm-kill-switch-v1.md.
		os.Exit(cmdWasmKillswitch(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println(versionString)
		return
	case "--help", "-h", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: daal-publish <command> [flags]")
	fmt.Fprintln(os.Stderr, "  keygen      generate a publisher root key")
	fmt.Fprintln(os.Stderr, "  subkey            issue a sub-key signed by a root key")
	fmt.Fprintln(os.Stderr, "  subkey rotate     rotate the active sub-key (FRP-7.5; default validity 90d)")
	fmt.Fprintln(os.Stderr, "  bundle      build a signed .sbp (Phase 3F: --redistribution-policy / --delegate-cap)")
	fmt.Fprintln(os.Stderr, "  verify      verify a .sbp")
	fmt.Fprintln(os.Stderr, "  revoke      sign a revocation list")
	fmt.Fprintln(os.Stderr, "  rotate-key  produce a rotation chain (signed by the old root)")
	fmt.Fprintln(os.Stderr, "  fingerprint print fingerprints for a publisher.pub file")
	fmt.Fprintln(os.Stderr, "  webtunnel-bridge  emit a WebTunnel route stub from a bridge URL (Phase 3A)")
	fmt.Fprintln(os.Stderr, "  snowflake-rendezvous-hint  sign a Snowflake offline rendezvous hint (Phase 3B)")
	fmt.Fprintln(os.Stderr, "  masque-bridge  emit a MASQUE route stub from an upstream endpoint URL (Phase 3C)")
	fmt.Fprintln(os.Stderr, "  psiphon-bundle  wrap an upstream Psiphon publisher bundle into a Daal route stub (Phase 3D)")
	fmt.Fprintln(os.Stderr, "  conjure-bridge  emit a Conjure route stub from a station + phantom-pool selection (Phase 3D)")
	fmt.Fprintln(os.Stderr, "  wasm-module     wrap a .wasm blob into a transport_modules[] entry + paired route stub (Phase 3E)")
	fmt.Fprintln(os.Stderr, "  wasm-killswitch sign a (slug, sha256, generation) WASM kill-switch delta (Phase 3E)")
	fmt.Fprintln(os.Stderr, "  version     print version")
}

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out-dir", "", "keystore output directory")
	label := fs.String("label", "", "human-readable label")
	force := fs.Bool("force", false, "overwrite existing publisher.priv")
	hsm := fs.Bool("hsm", false, "use a hardware token (reserved; not yet implemented)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *hsm {
		fmt.Fprintln(os.Stderr, "error: --hsm is reserved; HSM integration is not yet implemented")
		return 1
	}
	meta, err := publisher.Keygen(publisher.KeygenOptions{OutDir: *out, Label: *label, Force: *force})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Publisher key created.\n  hex: %s\n   en: %s\n   fa: %s\n", meta.KeyFingerprintHex, meta.KeyFingerprintEN, meta.KeyFingerprintFA)
	return 0
}

func cmdSubkey(args []string) int {
	// FRP-7.5 dispatch: `daal-publish subkey rotate ...` is the
	// rotation form (mints a fresh sub-key + cert and reports the
	// keystore paths). `daal-publish subkey ...` (no
	// sub-subcommand) is the original 1A "issue" form, retained
	// for backward compatibility.
	if len(args) > 0 && args[0] == "rotate" {
		return cmdSubkeyRotate(args[1:])
	}
	return cmdSubkeyIssue(args)
}

func cmdSubkeyIssue(args []string) int {
	fs := flag.NewFlagSet("subkey", flag.ContinueOnError)
	rootPriv := fs.String("root-priv", "", "path to publisher.priv")
	out := fs.String("out-dir", "", "keystore output directory")
	validity := fs.String("validity", "", "subkey validity (e.g., 14d, 2w, 336h)")
	label := fs.String("label", "", "human-readable label")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dur, err := publisher.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	art, err := publisher.Subkey(publisher.SubkeyOptions{
		RootPrivPath: *rootPriv, OutDir: *out, Validity: dur, Label: *label,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Subkey issued.\n  cert:   %s\n  pub:    %s\n  priv:   %s\n", art.SubkeyCertPath, art.SubkeyPubPath, art.SubkeyPrivPath)
	return 0
}

// cmdSubkeyRotate implements the FRP-7.5 `daal-publish subkey
// rotate` subcommand. It is the operator-facing entry point for
// the wizard's "Settings → Rotate sub-key" surface and for
// non-wizard scripted rotation. Differences from
// `daal-publish subkey` (the 1A issue form):
//
//   - Default validity 90d (vs no default; the issue form
//     required --validity to be set explicitly).
//   - Emits a JSON line on stdout with the keystore paths +
//     fingerprints + validity window so the wizard can parse
//     the result without re-loading from disk.
//   - The contract is otherwise the same: shell out, mint a new
//     sub-key, sign a cert with the supplied root key, write
//     subkey.{pub,priv,cert,meta.json} into out-dir/subkeys/<fp>/.
//
// Per supplement Position B: no network IO; root never leaves
// the FRP machine.
func cmdSubkeyRotate(args []string) int {
	fs := flag.NewFlagSet("subkey rotate", flag.ContinueOnError)
	rootPriv := fs.String("root-priv", "", "path to publisher.priv")
	out := fs.String("out-dir", "", "keystore output directory")
	validity := fs.String("validity", "90d", "subkey validity (e.g., 14d, 2w, 336h, 90d default)")
	label := fs.String("label", "rotated-subkey", "human-readable label")
	jsonOut := fs.Bool("json", false, "emit a single JSON line on stdout instead of the human-readable form")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *rootPriv == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "error: --root-priv and --out-dir are required")
		return 2
	}
	dur, err := publisher.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	art, err := publisher.Subkey(publisher.SubkeyOptions{
		RootPrivPath: *rootPriv, OutDir: *out, Validity: dur, Label: *label,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *jsonOut {
		// Compact JSON line for wizard / scripted callers. Field
		// names match client-ui/src/wizard/types.ts
		// SubkeyRotateResult so the bridge can deserialise
		// without an extra translation step.
		fmt.Printf("{"+
			"\"subkey_dir\":%q,"+
			"\"subkey_pub_path\":%q,"+
			"\"subkey_priv_path\":%q,"+
			"\"subkey_cert_path\":%q,"+
			"\"subkey_meta_path\":%q,"+
			"\"valid_from\":%q,"+
			"\"valid_until\":%q,"+
			"\"label\":%q,"+
			"\"root_fingerprint_hex\":%q,"+
			"\"subkey_fingerprint_hex\":%q"+
			"}\n",
			art.SubkeyDir, art.SubkeyPubPath, art.SubkeyPrivPath,
			art.SubkeyCertPath, art.SubkeyMetaPath,
			art.Cert.ValidFrom, art.Cert.ValidUntil, art.Cert.Label,
			art.Cert.RootFingerprintHex,
			bundle.PublisherFingerprint(art.SubkeyPubBytes).Hex,
		)
		return 0
	}
	fmt.Printf("Subkey rotated.\n  cert:        %s\n  pub:         %s\n  priv:        %s\n  valid until: %s\n",
		art.SubkeyCertPath, art.SubkeyPubPath, art.SubkeyPrivPath, art.Cert.ValidUntil)
	return 0
}

func cmdBundle(args []string) int {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "manifest.json path")
	profilesDir := fs.String("profiles-dir", "", "directory with route profiles")
	signingPriv := fs.String("signing-priv", "", "private key path (root or certified sub-key)")
	publisherPub := fs.String("publisher-pub", "", "publisher.pub path")
	rotation := fs.String("rotation-chain", "", "optional path to rotation.json")
	revocation := fs.String("revocation", "", "optional path to revocation.json")
	out := fs.String("out", "", "output .sbp path")
	lintStrict := fs.Bool("lint-strict", false, "treat lint warnings as errors")
	unsafe := fs.Bool("unsafe-unsigned", false, "DEVELOPMENT ONLY; produce *.UNSIGNED.sbp")
	legacyV1 := fs.Bool("legacy-v1", false, "produce a spec_version 1 manifest (Phase 1A/1B/1C/1D compatibility)")
	// Phase 3F. See specs/publisher-cli-v1.md "Phase 3F" and
	// specs/delegate-keys-v1.md.
	redistPolicy := fs.String("redistribution-policy", "",
		"per-route re-share policy: one of {none, delegated_n, transitive}; absent leaves the manifest unchanged (Phase 3F)")
	delegateCap := fs.Uint("delegate-cap", 0,
		"per-route re-share cap (1..255) when --redistribution-policy=delegated_n (Phase 3F)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *delegateCap > 255 {
		fmt.Fprintln(os.Stderr, "error: --delegate-cap must be in [1, 255]")
		return 2
	}
	if *unsafe {
		fmt.Fprintln(os.Stderr, "WARNING: --unsafe-unsigned is set. Output will be production-incompatible.")
		fmt.Fprintln(os.Stderr, "         The bundle library refuses to verify unsigned output.")
		if !strings.HasSuffix(*out, ".UNSIGNED.sbp") {
			fmt.Fprintln(os.Stderr, "error: --out must end in .UNSIGNED.sbp when --unsafe-unsigned is set")
			return 1
		}
	}
	res, err := publisher.Bundle(publisher.BundleOptions{
		ManifestPath:         *manifest,
		ProfilesDir:          *profilesDir,
		SigningPrivPath:      *signingPriv,
		PublisherPubPath:     *publisherPub,
		RotationChain:        *rotation,
		Revocation:           *revocation,
		Out:                  *out,
		LintStrict:           *lintStrict,
		UnsafeUnsigned:       *unsafe,
		LegacyV1:             *legacyV1,
		RedistributionPolicy: *redistPolicy,
		RedistributionCap:    uint8(*delegateCap),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	for _, f := range res.LintFindings {
		fmt.Fprintf(os.Stderr, "[lint %s %s] %s (%s)\n", f.Level, f.Code, f.Reason, f.Anchor)
	}
	pubFP := res.PublisherFP
	pub, _ := publisher.LoadPub(*publisherPub)
	rendered, _ := bundle.RenderFingerprint(bundle.PublisherFingerprint(pub), publisher.DefaultWordlists())
	fmt.Printf("Bundle written: %s (%d routes)\n", res.OutPath, res.RouteCount)
	fmt.Printf("Publisher fingerprint:\n  hex: %s\n   en: %s\n   fa: %s\n", pubFP, rendered.EN, rendered.FA)
	return 0
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	requireClass := fs.String("require-trust-class", "", "require trust_class to match")
	maxRoutes := fs.Int("max-route-count", 0, "reject bundles with more routes")
	rejectOnWarn := fs.Bool("reject-on-warn", false, "fail on lint warnings")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: daal-publish verify <file.sbp> [flags]")
		return 2
	}
	res, err := publisher.Verify(publisher.VerifyOptions{
		Path:              rest[0],
		RequireTrustClass: *requireClass,
		MaxRouteCount:     *maxRoutes,
		RejectOnWarn:      *rejectOnWarn,
	})
	if res != nil {
		publisher.WriteRedactedSummary(os.Stdout, res)
	}
	if err != nil {
		switch {
		case err == publisher.ErrPolicyDenied:
			return 2
		case err == publisher.ErrLintWarnings:
			return 3
		default:
			return 2
		}
	}
	return 0
}

func cmdRevoke(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	rootPriv := fs.String("root-priv", "", "publisher.priv path")
	reason := fs.String("reason", "", "human-readable reason")
	out := fs.String("out", "", "output revocation.json path")
	var bundleIDs, routeIDs, fps stringList
	fs.Var(&bundleIDs, "bundle-id", "(repeatable) bundle id to revoke")
	fs.Var(&routeIDs, "route-id", "(repeatable) route id to revoke")
	fs.Var(&fps, "publisher-fingerprint", "(repeatable) publisher fingerprint to revoke")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_, err := publisher.Revoke(publisher.RevokeOptions{
		RootPrivPath: *rootPriv, BundleIDs: bundleIDs, RouteIDs: routeIDs,
		PublisherFingerprints: fps, Reason: *reason, Out: *out,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Revocation written: %s\n", *out)
	return 0
}

func cmdRotateKey(args []string) int {
	fs := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
	oldPriv := fs.String("old-root-priv", "", "old root private key path")
	newPub := fs.String("new-root-pub", "", "new root public key path")
	window := fs.String("transition-window", "", "transition window duration (e.g., 14d)")
	out := fs.String("out", "", "output rotation.json path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dur, err := publisher.ParseDuration(*window)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if _, err := publisher.Rotate(publisher.RotateOptions{
		OldRootPrivPath: *oldPriv, NewRootPubPath: *newPub,
		TransitionWindow: dur, Out: *out,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Rotation chain written: %s\n", *out)
	return 0
}

func cmdFingerprint(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: daal-publish fingerprint <publisher.pub>")
		return 2
	}
	pub, err := publisher.LoadPub(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fp := bundle.PublisherFingerprint(pub)
	rendered, _ := bundle.RenderFingerprint(fp, publisher.DefaultWordlists())
	fmt.Printf("hex: %s\n en: %s\n fa: %s\n", fp.Hex, rendered.EN, rendered.FA)
	return 0
}

// stringList is a flag.Value supporting repeated string flags.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// cmdWebTunnelBridge emits a WebTunnel route stub from a bridge
// URL. Phase 3A. The output is a single route entry in
// manifest.routes[] shape, ready to splice into a manifest.json
// before running `daal-publish bundle`.
func cmdWebTunnelBridge(args []string) int {
	fs := flag.NewFlagSet("webtunnel-bridge", flag.ContinueOnError)
	urlStr := fs.String("url", "", "bridge URL: https://host[:port]/secret/path (required)")
	routeID := fs.String("route-id", "", "route id (default: wt-<host>)")
	validity := fs.String("validity", "7d", "route validity (e.g., 7d, 168h)")
	alpn := fs.String("alpn", "http/1.1", "comma-separated ALPN list (default: http/1.1)")
	caveat := fs.String("caveat-fa-ir", "", "Iranian region caveat override (Persian or empty)")
	minVer := fs.String("experimental-min-engine-version", "",
		"minimum engine semver required to select this route (e.g., 0.7.0)")
	out := fs.String("out", "", "path to write the route-stub JSON (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "error: --out is required")
		return 2
	}
	dur, err := publisher.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: --validity:", err)
		return 1
	}
	alpnList := splitNonEmpty(*alpn, ",")
	stub, host, err := publisher.WebTunnelBridge(publisher.WebTunnelBridgeOptions{
		URL:                          *urlStr,
		RouteID:                      *routeID,
		Validity:                     dur,
		ALPN:                         alpnList,
		CaveatFAIR:                   *caveat,
		ExperimentalMinEngineVersion: *minVer,
		OutPath:                      *out,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("WebTunnel route stub written: %s\n", *out)
	fmt.Printf("  route_id: %s\n  host:     %s\n", stub.ID, host)
	return 0
}

// cmdSnowflakeRendezvousHint emits a publisher-signed offline
// Snowflake rendezvous-hint envelope. Phase 3B. Output is one
// JSON object suitable for splicing into the
// manifest.rendezvous_hints[] slot.
func cmdSnowflakeRendezvousHint(args []string) int {
	fs := flag.NewFlagSet("snowflake-rendezvous-hint", flag.ContinueOnError)
	bridge := fs.String("bridge", "", "Snowflake bridge endpoint host:port (required)")
	fp := fs.String("fingerprint", "", "bridge cert fingerprint hex (required)")
	validity := fs.String("validity", "30d", "hint validity (default 30d)")
	out := fs.String("out", "", "path to write the signed hint envelope JSON (required)")
	key := fs.String("key", "", "publisher.priv path (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dur, err := publisher.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: --validity:", err)
		return 1
	}
	env, err := publisher.SnowflakeRendezvousHint(publisher.SnowflakeHintOptions{
		Bridge:         *bridge,
		FingerprintHex: *fp,
		Validity:       dur,
		OutPath:        *out,
		PrivKeyPath:    *key,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Snowflake rendezvous hint written: %s\n", *out)
	fmt.Printf("  bridge:    %s\n", *bridge)
	fmt.Printf("  payload:   %d bytes (signed)\n", len(env.Payload))
	return 0
}

// cmdMasqueBridge emits a MASQUE route stub from an upstream
// endpoint URL. Phase 3C. The output is a single route entry in
// manifest.routes[] shape, ready to splice into a manifest.json
// before running `daal-publish bundle`.
func cmdMasqueBridge(args []string) int {
	fs := flag.NewFlagSet("masque-bridge", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "", "MASQUE endpoint URL: https://host[:port]/path (required)")
	routeID := fs.String("route-id", "", "route id (default: mq-<host>)")
	validity := fs.String("validity", "7d", "route validity (e.g., 7d, 168h)")
	caveat := fs.String("caveat-fa-ir", "", "Iranian region caveat override (Persian or empty)")
	minVer := fs.String("experimental-min-engine-version", "",
		"minimum engine semver required to select this route (e.g., 0.7.2)")
	out := fs.String("out", "", "path to write the route-stub JSON (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "error: --out is required")
		return 2
	}
	dur, err := publisher.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: --validity:", err)
		return 1
	}
	stub, host, err := publisher.MasqueBridge(publisher.MasqueBridgeOptions{
		Endpoint:                     *endpoint,
		RouteID:                      *routeID,
		Validity:                     dur,
		CaveatFAIR:                   *caveat,
		ExperimentalMinEngineVersion: *minVer,
		OutPath:                      *out,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("MASQUE route stub written: %s\n", *out)
	fmt.Printf("  route_id: %s\n  host:     %s\n", stub.ID, host)
	return 0
}

// cmdPsiphonBundle wraps an upstream Psiphon publisher bundle
// blob (produced out-of-band by Psiphon Inc.'s tooling) into a
// Daal route stub. Phase 3D. The output is a single route
// entry in manifest.routes[] shape, ready to splice into a
// manifest.json before running `daal-publish bundle`.
func cmdPsiphonBundle(args []string) int {
	fs := flag.NewFlagSet("psiphon-bundle", flag.ContinueOnError)
	blobPath := fs.String("psiphon-blob", "", "path to the upstream Psiphon publisher bundle blob (required)")
	routeID := fs.String("route-id", "", "route id (default: ps-<blob-checksum-prefix>)")
	validity := fs.String("validity", "7d", "route validity (e.g., 7d, 168h)")
	scarcity := fs.String("scarcity", "normal", "route scarcity_class (normal|experimental); 'emergency' is rejected for psiphon")
	caveat := fs.String("caveat-fa-ir", "", "Iranian region caveat override (Persian or empty)")
	minVer := fs.String("experimental-min-engine-version", "",
		"minimum engine semver required to select this route (e.g., 0.7.3)")
	out := fs.String("out", "", "path to write the route-stub JSON (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "error: --out is required")
		return 2
	}
	dur, err := publisher.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: --validity:", err)
		return 1
	}
	stub, checksum, err := publisher.PsiphonBundle(publisher.PsiphonBundleOptions{
		BlobPath:                     *blobPath,
		RouteID:                      *routeID,
		Validity:                     dur,
		ScarcityClass:                *scarcity,
		CaveatFAIR:                   *caveat,
		ExperimentalMinEngineVersion: *minVer,
		OutPath:                      *out,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Psiphon route stub written: %s\n", *out)
	fmt.Printf("  route_id:  %s\n  checksum:  %s\n", stub.ID, checksum)
	return 0
}

// cmdConjureBridge emits a Conjure route stub from a station
// public key + phantom-pool selection. Phase 3D. The output is
// a single route entry in manifest.routes[] shape, ready to
// splice into a manifest.json before running `daal-publish
// bundle`. Phantom-subnet prefix-length floors are locked at
// /24 IPv4 and /32 IPv6 per specs/conjure-route-v1.md.
func cmdConjureBridge(args []string) int {
	fs := flag.NewFlagSet("conjure-bridge", flag.ContinueOnError)
	pubkey := fs.String("station-pubkey", "", "Conjure station curve25519 pubkey, hex (64 chars; required)")
	subnets := fs.String("phantom-subnets", "",
		"comma-separated phantom-pool CIDRs (>= /24 IPv4, >= /32 IPv6; required)")
	decoys := fs.String("decoy-pool", "", "optional comma-separated RFC 1123 decoy hostnames")
	routeID := fs.String("route-id", "", "route id (default: cj-<pubkey-prefix>)")
	validity := fs.String("validity", "7d", "route validity (e.g., 7d, 168h)")
	scarcity := fs.String("scarcity", "experimental", "route scarcity_class (default: experimental)")
	caveat := fs.String("caveat-fa-ir", "", "Iranian region caveat override (Persian or empty)")
	minVer := fs.String("experimental-min-engine-version", "",
		"minimum engine semver required to select this route (e.g., 0.7.3)")
	out := fs.String("out", "", "path to write the route-stub JSON (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "error: --out is required")
		return 2
	}
	dur, err := publisher.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: --validity:", err)
		return 1
	}
	stub, fpPrefix, err := publisher.ConjureBridge(publisher.ConjureBridgeOptions{
		StationPubkey:                *pubkey,
		PhantomSubnets:               splitNonEmpty(*subnets, ","),
		DecoyPool:                    splitNonEmpty(*decoys, ","),
		RouteID:                      *routeID,
		Validity:                     dur,
		ScarcityClass:                *scarcity,
		CaveatFAIR:                   *caveat,
		ExperimentalMinEngineVersion: *minVer,
		OutPath:                      *out,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Conjure route stub written: %s\n", *out)
	fmt.Printf("  route_id:    %s\n  station_fp:  %s\n", stub.ID, fpPrefix)
	return 0
}

// cmdWasmModule wraps a `.wasm` file into a transport_modules[]
// entry stub plus a paired routes[] entry stub. Phase 3E.
func cmdWasmModule(args []string) int {
	fs := flag.NewFlagSet("wasm-module", flag.ContinueOnError)
	wasmPath := fs.String("wasm", "", "path to the compiled .wasm blob (required)")
	slug := fs.String("slug", "", "module slug, [a-z0-9_-]{3,32} (required)")
	routeID := fs.String("route-id", "", "route id (default: tm-<slug>)")
	validity := fs.String("validity", "7d", "route validity (e.g., 7d, 168h)")
	scarcity := fs.String("scarcity", "experimental", "route scarcity_class (default: experimental); 'emergency' rejected")
	caveat := fs.String("caveat-fa-ir", "", "Iranian region caveat override (Persian or empty)")
	minVer := fs.String("experimental-min-engine-version", "",
		"minimum engine semver required to select this route (e.g., 0.8.0)")
	modMinVer := fs.String("min-engine-version", "0.8.0",
		"the module's own min-engine-version pin (semver; default 0.8.0)")
	outMod := fs.String("out-module", "", "path to write the transport_modules entry JSON (required)")
	outRoute := fs.String("out-route", "", "path to write the paired route-stub JSON (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dur, err := publisher.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: --validity:", err)
		return 1
	}
	entry, route, prefix, err := publisher.WasmModule(publisher.WasmModuleOptions{
		WasmPath:                     *wasmPath,
		Slug:                         *slug,
		RouteID:                      *routeID,
		Validity:                     dur,
		ScarcityClass:                *scarcity,
		CaveatFAIR:                   *caveat,
		ExperimentalMinEngineVersion: *minVer,
		MinEngineVersion:             *modMinVer,
		OutModulePath:                *outMod,
		OutRoutePath:                 *outRoute,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("WASM module entry written: %s\n", *outMod)
	fmt.Printf("WASM route stub written:  %s\n", *outRoute)
	fmt.Printf("  slug:        %s\n  sha256_pfx:  %s\n  route_id:    %s\n",
		entry.Slug, prefix, route.ID)
	return 0
}

// cmdWasmKillswitch signs a (slug, sha256, generation) tuple
// under the project-controlled kill-switch private key. Phase
// 3E.
func cmdWasmKillswitch(args []string) int {
	fs := flag.NewFlagSet("wasm-killswitch", flag.ContinueOnError)
	slug := fs.String("slug", "", "module slug to kill (required)")
	sha := fs.String("sha256", "", "module sha256 hex (64 chars; required)")
	gen := fs.Uint64("generation", 0, "monotonically-increasing generation counter (required, > 0)")
	keyPath := fs.String("key", "",
		"path to the WASM kill-switch Ed25519 private key (raw 64 bytes or hex; required)")
	out := fs.String("out", "", "path to write the signed delta JSON (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	entry, fp, err := publisher.WasmKillswitch(publisher.WasmKillswitchOptions{
		Slug:       *slug,
		SHA256Hex:  *sha,
		Generation: *gen,
		KeyPath:    *keyPath,
		OutPath:    *out,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("WASM kill-switch delta written: %s\n", *out)
	fmt.Printf("  slug:        %s\n  generation:  %d\n  pub_fp:      %s\n",
		entry.Slug, entry.Generation, fp)
	return 0
}

func splitNonEmpty(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
