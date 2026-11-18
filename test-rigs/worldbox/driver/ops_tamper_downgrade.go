package main

// ops_tamper_downgrade.go — a commitment is sticky.
//
// A bundle with no relay_pack slot carries profiles that no signature
// covers (specs/sbp-v1.md "What the signature covers"). So whoever holds
// ONE genuine, unexpired bundle of that kind from a publisher can
// rewrite its profiles without any key. If that bundle names the route
// ids of a RelayPack the phone already holds, importing it must not
// replace those routes: they are checked against the publisher's signed
// endpoint, and what would replace them is checked against nothing.
//
// The publisher key IS used here, and only for what the publisher would
// have done themselves: sign a plain bundle. The rewrite that follows
// uses no key.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"daal/bundle-go/bundle"
)

const endpointDowngrade = "endpoint_downgrade"

func tamperDowngrade(rc *RunCtx, phase string, src []byte) {
	const label = "uncommitted_replacement"
	t0 := time.Now()
	fail := func(check, why string) { rc.R.Add("", phase, label+"."+check, Pass, Fail, why, nil, t0) }

	b, err := bundle.ParseSBP(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		fail("control.new_routes.import", "the rig could not parse the pack: "+err.Error())
		return
	}
	privRaw, _ := os.ReadFile(rc.Pub.Path("publisher.priv"))
	if len(privRaw) != ed25519.PrivateKeySize {
		fail("control.new_routes.import", "publisher.priv is not an Ed25519 private key")
		return
	}
	priv := ed25519.PrivateKey(privRaw)
	pub := priv.Public().(ed25519.PublicKey)

	// plain is the publisher's own bundle with no relay_pack slot and no
	// commitments, for the route ids rename() yields.
	plain := func(id string, rename func(string) string) ([]byte, int, error) {
		m := b.Manifest
		m.RelayPack = nil
		m.Bundle.ID = id
		m.Bundle.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		m.Routes = nil
		profiles := map[string][]byte{}
		for _, r := range bundle.UsableRoutes(b) {
			r.ID = rename(r.ID)
			r.FamilySpecificConfig = nil
			r.ConfigPath = "profiles/" + r.ID + ".json"
			m.Routes = append(m.Routes, r)
			profiles[r.ConfigPath] = []byte(`{"type":"direct"}`)
		}
		body, err := bundle.BuildSignedBundle(m, profiles, pub, priv)
		return body, len(m.Routes), err
	}

	c, err := StartClient(rc.P, "tamper-downgrade", ClientOpts{Pack: rc.Pack, Idle: true, Experimental: true})
	if err != nil {
		fail("control.new_routes.import", err.Error())
		return
	}
	defer c.Stop()
	if _, err := c.Wait(rc.Ctx, 20*time.Second, "idle"); err != nil {
		fail("control.new_routes.import", "pack not imported: "+err.Error())
		return
	}
	importFile := func(name string, body []byte) (map[string]any, error) {
		p, err := writeTampered(rc, name, body)
		if err != nil {
			return nil, err
		}
		_ = c.Send("import " + p)
		return c.Wait(rc.Ctx, 20*time.Second, "reimport")
	}

	// Control: the same kind of bundle, for routes the phone does not
	// hold, is taken. Without this the refusal below proves nothing.
	ctl, n, err := plain("wb-plain-new-routes", func(id string) string { return "wb-plain-" + id })
	if err != nil || n == 0 {
		fail("control.new_routes.import", fmt.Sprintf("could not build the plain bundle (routes=%d, err=%v)", n, err))
		return
	}
	ev, err := importFile("bundle-plain-new-routes.sbp", ctl)
	if err != nil {
		fail("control.new_routes.import", "the import did not return: "+err.Error())
		return
	}
	kind, _ := ev["kind"].(string)
	if !rc.R.Add("", phase, label+".control.new_routes.import", Pass, got(kind == "imported", Pass, Fail),
		got(kind == "imported", "", fmt.Sprintf("a plain bundle of the same publisher for NEW route ids was not imported (kind=%s reason=%v error=%v)", kind, ev["reason"], ev["error"])),
		map[string]any{"kind": kind, "routes": n, "signed_by": "the publisher"}, t0) {
		return
	}
	held := routeDigest(ev["routes"])

	// The attack: the publisher's plain bundle for the SAME route ids,
	// its profiles then rewritten with no key.
	t0 = time.Now()
	same, n, err := plain("wb-plain-same-routes", func(id string) string { return id })
	if err != nil || n == 0 {
		fail("import", fmt.Sprintf("could not build the plain bundle (routes=%d, err=%v)", n, err))
		return
	}
	const attacker = "198.51.100.66"
	rewritten := 0
	attack, err := rewritePack(same, func(name string, body []byte) []byte {
		if len(name) > len("profiles/") && name[:len("profiles/")] == "profiles/" {
			rewritten++
			return []byte(`{"type":"vless","tag":"active","server":"` + attacker + `","server_port":443,` +
				`"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"insecure":true}}`)
		}
		return body
	})
	if err != nil || rewritten == 0 {
		fail("import", fmt.Sprintf("could not rewrite the plain bundle (rewritten=%d, err=%v)", rewritten, err))
		return
	}
	ev, err = importFile("bundle-plain-same-routes-rewritten.sbp", attack)
	if err != nil {
		fail("import", "the import did not return: "+err.Error())
		return
	}
	kind, _ = ev["kind"].(string)
	reason, _ := ev["reason"].(string)
	refused := kind == "rejected" && reason == endpointDowngrade
	rc.R.Add("", phase, label+".import", Refused, got(refused, Refused, got(kind == "imported", Pass, Fail)),
		got(refused, "", got(kind == "imported",
			"a bundle with no signed endpoints, its profiles rewritten without any key, replaced routes the phone held under a signed endpoint — silently, the publisher being already trusted",
			fmt.Sprintf("not refused as %s: kind=%s reason=%q error=%v", endpointDowngrade, kind, reason, ev["error"]))),
		map[string]any{"kind": kind, "reason_code": reason, "profiles_rewritten": rewritten, "server_now": attacker,
			"keys_used": "none for the rewrite; the bundle itself is the publisher's own", "client_dir": c.Dir}, t0)
	after := routeDigest(ev["routes"])
	rc.R.Add("", phase, label+".routes_kept", Pass, got(held != "" && held == after, Pass, Fail),
		got(held == after, "", "the route list changed across a refused import: before "+held+", after "+after), nil, t0)
}

// routeDigest is the engine's route list as one comparable string (every
// field it reports, so a route that kept its id and lost its pack shows).
func routeDigest(v any) string {
	doc, _ := v.(map[string]any)
	routes, _ := doc["routes"].([]any)
	if len(routes) == 0 {
		return ""
	}
	out, _ := json.Marshal(routes)
	return string(out)
}
