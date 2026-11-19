package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// `wb mgmtprobe` is somebody talking to a relay's management API by hand:
// hand-built requests, hand-built Daal-Mgmt-Token headers. It exists for
// the requests the REAL publisher can never be made to send — unsigned,
// signed by the wrong key, signed for another endpoint, stale, replayed.
// Everything the publisher legitimately does goes through daal-deploy,
// never through here.
//
// It reads a JSON list of requests on stdin and prints a JSON list of
// answers. Token shape is the product's wire contract
// (specs/daal-relay-mgmt-v1.md §3, publisher/deploy/mgmt/token.go):
//
//	v2:<nonce>:<unix ts>:<op>:<base64 ed25519 sig>
//
// where the signature covers eight lines joined by "\n":
// "daal-mgmt-token-v2", relay, nonce, ts, op, METHOD, path, hex
// sha256(body) - relay being the lower-case hex SHA-256 of the mgmt TLS
// certificate of the relay the token is for (--fpr).
// Re-stated here on purpose: a probe that imported the product's minter
// could not mint a token the product refuses to mint — one signed for
// another body (SignBody), for another relay (SignRelay), or the retired v1 shape that did not sign the
// request at all (Format "v1": "<nonce>:<ts>:<op>:<sig over nonce:ts:op>").
//
// TLS: the box's certificate is self-signed and the publisher pins its
// SHA-256. The probe pins the same fingerprint (--fpr) and reports a
// mismatch instead of talking to the wrong thing.

// MgmtReq is one hand-built request.
type MgmtReq struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body,omitempty"`
	// Token: "" = no Authorization header at all; "raw:<text>" = that
	// literal header value after "Daal-Mgmt-Token "; "sign" = mint one
	// with Key/Op/TSOffset; "reuse:<id>" = the exact token an earlier
	// request in this batch presented.
	Token    string `json:"token,omitempty"`
	Key      string `json:"key,omitempty"`       // "publisher" (default) | "stranger"
	Op       string `json:"op,omitempty"`        // the op string that is SIGNED
	TSOffset int64  `json:"ts_offset,omitempty"` // seconds added to now before signing
	// Scheme overrides the Authorization scheme word ("Daal-Mgmt-Token").
	Scheme string `json:"scheme,omitempty"`
	// SignBody, when set, is the body the token is signed FOR while Body
	// is what is sent: a token minted for one request, presented with
	// another. Empty = sign what is sent.
	SignBody string `json:"sign_body,omitempty"`
	// SignRelay, when set, is the relay the token is signed FOR (a mgmt
	// TLS fingerprint) while it is presented to this one: a token the
	// publisher minted for another relay that trusts the same key.
	// Empty = sign for the relay being talked to (--fpr).
	SignRelay string `json:"sign_relay,omitempty"`
	// Format "v1" mints the retired token shape (signature over
	// nonce:ts:op only). Default: v2.
	Format string `json:"format,omitempty"`
}

// MgmtAns is the box's answer.
type MgmtAns struct {
	ID     string `json:"id"`
	Status int    `json:"status"` // 0 = no HTTP answer at all
	Body   string `json:"body"`
	Error  string `json:"error,omitempty"`
}

func cmdMgmtProbe(args []string) int {
	fs := flag.NewFlagSet("mgmtprobe", flag.ExitOnError)
	addr := fs.String("addr", "", "ip:port of the mgmt API")
	fpr := fs.String("fpr", "", "pinned SHA-256 of the mgmt TLS certificate (hex)")
	privFile := fs.String("priv", "", "publisher Ed25519 private key (64 raw bytes)")
	_ = fs.Parse(args)

	var reqs []MgmtReq
	if err := json.NewDecoder(os.Stdin).Decode(&reqs); err != nil {
		fmt.Fprintln(os.Stderr, "mgmtprobe: stdin:", err)
		return 2
	}
	pubPriv, err := os.ReadFile(*privFile)
	if err != nil || len(pubPriv) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "mgmtprobe: --priv must be a 64-byte Ed25519 private key:", err)
		return 2
	}
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)

	pinErr := ""
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // self-signed by design; pinned below, as the publisher does
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return fmt.Errorf("no certificate")
				}
				sum := sha256.Sum256(raw[0])
				if got := hex.EncodeToString(sum[:]); *fpr != "" && got != *fpr {
					pinErr = "mgmt TLS fingerprint " + got + " is not the pinned " + *fpr
					return fmt.Errorf("%s", pinErr)
				}
				return nil
			},
		},
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	sent := map[string]string{}
	out := make([]MgmtAns, 0, len(reqs))
	for _, q := range reqs {
		ans := MgmtAns{ID: q.ID}
		var body io.Reader
		if q.Body != "" {
			body = bytes.NewReader([]byte(q.Body))
		}
		req, err := http.NewRequestWithContext(context.Background(), q.Method, "https://"+*addr+q.Path, body)
		if err != nil {
			ans.Error = err.Error()
			out = append(out, ans)
			continue
		}
		if q.Body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		token := ""
		switch {
		case q.Token == "":
		case q.Token == "sign":
			key := ed25519.PrivateKey(pubPriv)
			if q.Key == "stranger" {
				key = strangerPriv
			}
			var nb [16]byte
			_, _ = rand.Read(nb[:])
			nonce := hex.EncodeToString(nb[:])
			ts := strconv.FormatInt(time.Now().Unix()+q.TSOffset, 10)
			if q.Format == "v1" {
				msg := nonce + ":" + ts + ":" + q.Op
				token = msg + ":" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(msg)))
				break
			}
			signed := q.Body
			if q.SignBody != "" {
				signed = q.SignBody
			}
			sum := sha256.Sum256([]byte(signed))
			relay := strings.ToLower(strings.TrimSpace(*fpr))
			if q.SignRelay != "" {
				relay = q.SignRelay
			}
			msg := strings.Join([]string{"daal-mgmt-token-v2", relay, nonce, ts, q.Op, q.Method, q.Path, hex.EncodeToString(sum[:])}, "\n")
			token = "v2:" + nonce + ":" + ts + ":" + q.Op + ":" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(msg)))
		case len(q.Token) > 4 && q.Token[:4] == "raw:":
			token = q.Token[4:]
		case len(q.Token) > 6 && q.Token[:6] == "reuse:":
			token = sent[q.Token[6:]]
			if token == "" {
				ans.Error = "no earlier token " + q.Token[6:]
				out = append(out, ans)
				continue
			}
		}
		if q.Token != "" {
			scheme := q.Scheme
			if scheme == "" {
				scheme = "Daal-Mgmt-Token"
			}
			req.Header.Set("Authorization", scheme+" "+token)
			sent[q.ID] = token
		}
		resp, err := client.Do(req)
		if err != nil {
			ans.Error = err.Error()
			out = append(out, ans)
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		ans.Status, ans.Body = resp.StatusCode, string(b)
		out = append(out, ans)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if pinErr != "" {
		return 1
	}
	return 0
}
