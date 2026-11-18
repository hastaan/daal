package main

import (
	"encoding/json"
	"os"
	"regexp"
	"time"
)

func init() { Ops["wrongcreds"] = opWrongCreds }

// opWrongCreds: a pack that is validly signed but carries credentials the
// relay never issued must not carry traffic.
//
// The pack is minted by the real `users-pack-sbp` from r1's real
// credential file with every secret replaced by a same-shape value: the
// UUIDs get a different last block, passwords/keys a different tail. The
// REALITY public key, cover SNI and TLS pins are left alone, so the
// handshake reaches the authentication step and it is the credential —
// not a broken config — that is refused.
func opWrongCreds(rc *RunCtx) {
	const phase = "op:wrongcreds"
	t0 := time.Now()
	body, err := os.ReadFile(rc.Pub.Path("creds-r1.json"))
	if err != nil {
		rc.R.Add("", phase, "forge", Pass, Fail, err.Error(), nil, t0)
		return
	}
	var creds map[string]any
	if err := json.Unmarshal(body, &creds); err != nil {
		rc.R.Add("", phase, "forge", Pass, Fail, err.Error(), nil, t0)
		return
	}
	uuidRe := regexp.MustCompile(`[0-9a-f]{12}$`)
	changed := []string{}
	for _, k := range []string{"vless_uuid", "tuic_uuid"} {
		if s, _ := creds[k].(string); s != "" {
			creds[k] = uuidRe.ReplaceAllString(s, "000000000bad")
			changed = append(changed, k)
		}
	}
	for _, k := range []string{"hy2_password", "naive_password", "tuic_password", "anytls_password"} {
		if s, _ := creds[k].(string); len(s) > 4 {
			creds[k] = s[:len(s)-4] + flip(s[len(s)-4:])
			changed = append(changed, k)
		}
	}
	// ss_password is "<box iPSK>:<recipient uPSK>", both base64: swap the
	// recipient half for a different valid key of the same length.
	if s, _ := creds["ss_password"].(string); s != "" {
		creds["ss_password"] = forgeSS(s)
		changed = append(changed, "ss_password")
	}
	forged, _ := json.Marshal(creds)
	if err := os.WriteFile(rc.Pub.Path("creds-forged.json"), forged, 0o600); err != nil {
		rc.R.Add("", phase, "forge", Pass, Fail, err.Error(), nil, t0)
		return
	}
	v := rc.Pub.PackSBP(rc.Ctx, "base.sbp", "creds-forged.json", "pack-forged.sbp")
	if !rc.R.Add("", phase, "forge", Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"fields_changed": changed}, t0) {
		return
	}
	for _, f := range rc.activeFamilies() {
		rc.sub(f, phase, "forged", rc.Pub.Path("pack-forged.sbp"), Blocked)
	}
}

func flip(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
	}
	return string(b)
}

func forgeSS(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			tail := []byte(s[i+1:])
			// keep base64 length/padding; change the leading characters
			for j := 0; j < len(tail) && j < 8; j++ {
				if tail[j] == 'A' {
					tail[j] = 'B'
				} else {
					tail[j] = 'A'
				}
			}
			return s[:i+1] + string(tail)
		}
	}
	return s
}
