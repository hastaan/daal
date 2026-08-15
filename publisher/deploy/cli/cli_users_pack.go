// FRP-14 Layer 3b.5: `daal-deploy users-pack-sbpx`.
//
// Wraps an existing signed `.sbp` plaintext in an age-v1 envelope
// addressed to one X25519 recipient (the `daal1…` pubkey). The
// result is a `.sbpx` file with the canonical `DSBP\x00\x01`
// magic prefix.
//
// Tier-1 wrap (FRP-14 Layer 3b.5): the inner `.sbp` is whatever
// the wizard's Step 6 produced — i.e. it still bakes in the
// publisher's *shared* sing-box credentials. The envelope adds
// in-transit confidentiality and binds the file to one recipient
// pubkey; per-recipient credential injection inside the inner
// bundle lands in Tier-2 (sbpx-envelope-v1 §10 / per-recipient-
// credentials-v1 §future).
package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"daal/bundle-go/envelope"
	"daal/publisher/deploy/relaypack"
)

// runUsersUnpackSbpx (Layer 3d) decrypts a `.sbpx` envelope on
// the recipient side. The recipient X25519 private key is piped
// in on stdin as 64 lowercase hex chars (no trailing newline
// strictly required; we trim).
func runUsersUnpackSbpx(_ context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("users-unpack-sbpx", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inPath := fs.String("in", "", "input .sbpx path")
	outPath := fs.String("out", "", "output plaintext .sbp path")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--in":  *inPath,
		"--out": *outPath,
	}); err != nil {
		return 2
	}

	// Read priv-key hex from stdin (single line). Length is
	// validated below.
	privBuf, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "read priv stdin: %v\n", err)
		return 1
	}
	privHex := string(privBuf)
	// Trim whitespace and trailing newline.
	privHex = trimAscii(privHex)
	if len(privHex) != 64 {
		fmt.Fprintf(stderr, "priv-key on stdin must be 64 hex chars (got %d)\n", len(privHex))
		return 2
	}
	rawPriv, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(stderr, "decode priv: %v\n", err)
		return 2
	}
	var priv [32]byte
	copy(priv[:], rawPriv)
	defer zeroBytes(rawPriv)
	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()

	ciphertext, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(stderr, "read input: %v\n", err)
		return 1
	}
	if !envelope.SniffMagic(ciphertext) {
		fmt.Fprintf(stderr, "not an .sbpx file (bad magic)\n")
		return 1
	}
	plaintext, err := envelope.Decrypt(ciphertext, priv)
	if err != nil {
		fmt.Fprintf(stderr, "decrypt: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*outPath, plaintext, 0o600); err != nil {
		fmt.Fprintf(stderr, "write output: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(map[string]any{
		"plaintext_path": *outPath,
		"plaintext_size": len(plaintext),
		"sbpx_size":      len(ciphertext),
	}); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}

func trimAscii(s string) string {
	for len(s) > 0 {
		c := s[len(s)-1]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	for len(s) > 0 {
		c := s[0]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			s = s[1:]
			continue
		}
		break
	}
	return s
}

// clientParamsFromCredsFile reads a per-recipient creds JSON (the mgmt
// /users/provision response shape) and maps it to the fields the client
// outbound assembler needs, with `server` supplied separately (the box
// public IP is not part of the creds payload).
func clientParamsFromCredsFile(path, server string) (relaypack.ClientConnParams, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return relaypack.ClientConnParams{}, err
	}
	var c struct {
		Name             string `json:"name"`
		VLESSUUID        string `json:"vless_uuid"`
		RealityShortID   string `json:"reality_short_id"`
		RealityPublicKey string `json:"reality_public_key"`
		Hy2Password      string `json:"hy2_password"`
		NaivePassword    string `json:"naive_password"`
		WSPath           string `json:"ws_path"`
		TLSCertSHA256    string `json:"tls_cert_sha256"`
		TLSCertPEM       string `json:"tls_cert_pem"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return relaypack.ClientConnParams{}, fmt.Errorf("parse: %w", err)
	}
	return relaypack.ClientConnParams{
		Server:           server,
		Name:             c.Name,
		VLESSUUID:        c.VLESSUUID,
		RealityShortID:   c.RealityShortID,
		RealityPublicKey: c.RealityPublicKey,
		Hy2Password:      c.Hy2Password,
		NaivePassword:    c.NaivePassword,
		WSPath:           c.WSPath,
		TLSCertSHA256:    c.TLSCertSHA256,
		TLSCertPEM:       c.TLSCertPEM,
	}, nil
}

func runUsersPackSbpx(_ context.Context, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("users-pack-sbpx", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inPath := fs.String("in", "", "input .sbp path (Step 6 output)")
	pubHex := fs.String("recipient-pub-hex", "", "recipient X25519 pubkey (64 lowercase hex chars)")
	outPath := fs.String("out", "", "output .sbpx path")
	// FRP-14 Tier-2: when both --creds-file and --server are given, the
	// inner .sbp's per-route profiles are rewritten with real client
	// sing-box outbounds for THIS recipient before enveloping. Omitting
	// them preserves the Tier-1 behaviour (envelope the .sbp unchanged).
	credsFile := fs.String("creds-file", "", "per-recipient creds JSON (mgmt /users/provision shape); enables Tier-2 profile rewrite")
	server := fs.String("server", "", "box public IP/host for the client outbound (required with --creds-file)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--in":                *inPath,
		"--recipient-pub-hex": *pubHex,
		"--out":               *outPath,
	}); err != nil {
		return 2
	}
	if len(*pubHex) != 64 {
		fmt.Fprintf(stderr, "recipient-pub-hex must be 64 hex chars (got %d)\n", len(*pubHex))
		return 2
	}
	raw, err := hex.DecodeString(*pubHex)
	if err != nil {
		fmt.Fprintf(stderr, "decode pubkey: %v\n", err)
		return 2
	}
	if len(raw) != 32 {
		fmt.Fprintf(stderr, "decoded pubkey is %d bytes, want 32\n", len(raw))
		return 2
	}
	var pub [32]byte
	copy(pub[:], raw)

	plaintext, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(stderr, "read input: %v\n", err)
		return 1
	}

	// FRP-14 Tier-2: rewrite the inner .sbp's profiles with real client
	// outbounds for this recipient before enveloping. Fails closed if a
	// route can't be made connectable — a pack must not ship a dead route.
	if *credsFile != "" {
		if *server == "" {
			fmt.Fprintln(stderr, "--server is required with --creds-file")
			return 2
		}
		params, err := clientParamsFromCredsFile(*credsFile, *server)
		if err != nil {
			fmt.Fprintf(stderr, "creds-file: %v\n", err)
			return 2
		}
		plaintext, err = relaypack.RewriteProfilesForRecipient(plaintext, params)
		if err != nil {
			fmt.Fprintf(stderr, "rewrite profiles: %v\n", err)
			return 1
		}
	}

	if len(plaintext) > envelope.MaxCiphertextBytes {
		fmt.Fprintf(stderr, "input .sbp is %d bytes; max %d\n",
			len(plaintext), envelope.MaxCiphertextBytes)
		return 1
	}

	wrapped, err := envelope.EncryptForRecipient(plaintext, pub)
	if err != nil {
		fmt.Fprintf(stderr, "encrypt: %v\n", err)
		return 1
	}
	// 0600 — the file may briefly live in shared staging on
	// platforms that don't restrict app-private dirs by default.
	if err := os.WriteFile(*outPath, wrapped, 0o600); err != nil {
		fmt.Fprintf(stderr, "write output: %v\n", err)
		return 1
	}

	if err := json.NewEncoder(stdout).Encode(map[string]any{
		"sbpx_path":      *outPath,
		"plaintext_size": len(plaintext),
		"sbpx_size":      len(wrapped),
	}); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}
