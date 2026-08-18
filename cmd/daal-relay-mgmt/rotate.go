// Step 7 — in-place rotation, split by blast radius.
//
// THE BUG THIS FILE EXISTS TO KILL. `/rotate-credentials` used to do two
// unrelated things in one call: it re-minted every recipient's VLESS UUID
// *and* it regenerated the box-wide REALITY keypair. Those have nothing in
// common except that both touch `tls`:
//
//   - Rotating ONE recipient's credentials is a targeted revocation. It
//     affects exactly one person. It is cheap, it is safe, and it is the
//     operation a publisher reaches for when a single pack leaks. Nobody
//     else's connection is invalidated.
//   - Rotating the box REALITY keypair invalidates the pinned public key in
//     EVERY pack that box ever emitted. Every recipient stops working until
//     each one is handed a new pack — and under blackout, hand-delivering a
//     file is precisely the thing that does not work. It is a last resort,
//     not a button.
//
// Conflating them means the cheap operation silently carries the expensive
// one's blast radius: press "rotate credentials" because r7's phone was
// seized and you have just severed r1..r6 as well. So the two are separated
// here, and box-keypair rotation is not implemented at all on this endpoint
// (see the note at the bottom of this file for where it has to live).
//
// THE OTHER HALF of the fix is per-recipient targeting. The pinned contract
// is `{"name":"r1"}`, and a MISSING name is an error — never "rotate all".
// A default that fans out is how a publisher accidentally severs their whole
// family with a mis-click, and it is also what an un-updated caller would
// send by accident: the pre-Step-7 publisher client posts a nil body, and the
// only safe reading of a nil body is "this caller does not know what it is
// asking for".
//
// SINGLE-INDEX RULE, again. Every rewriter here selects inbounds by TYPE and
// user rows by NAME, then loops. It never indexes. That rule is written out
// in full in main.go above the surgical* helpers; the Wave-2 fix to
// surgicalSetUUIDs (iterate every vless-family inbound and every user, not
// inbounds[0].users[0]) is the direct ancestor of rotateRecipientCreds below.
// A rotation that reaches three of the four inbounds leaves the recipient
// half-working, which is strictly worse than failing: the leaked credential
// keeps working on the tier that was missed, so the revocation revokes
// nothing while reporting success.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// errRecipientNotFound is returned when the named recipient owns no user row
// in any inbound. The handler maps it to 404 — distinct from a 500, because
// "you asked to rotate somebody who is not on this box" is a caller error and
// the operator needs to see that, not a generic failure.
var errRecipientNotFound = errors.New("recipient has no user row in this box's sing-box config")

// errNothingToRotate is returned by rewriteSingboxTLS when the request would
// leave the config byte-identical. Reported as 400 rather than a cheerful
// 200: a "rotation succeeded" toast over a no-op is how an operator concludes
// a burned cover host has been replaced when it has not.
var errNothingToRotate = errors.New("nothing to rotate")

// --- per-recipient credential rotation (targeted revocation) -------------

// credRotation records what a per-recipient rotation actually did, as
// opposed to what it intended to do. The distinction is load-bearing twice
// over: the publisher mints the replacement pack from Creds, so any field
// that reports an intent the box did not apply produces a pack the box
// refuses; and Inbounds is the only way a caller can tell a complete
// revocation from a partial one.
type credRotation struct {
	// Creds is the recipient's post-rotation credential set, read back from
	// what was written — including the values that were deliberately NOT
	// rotated (the shared ws path) and the ones that could not be (see
	// rotateShortIDs).
	Creds userCreds
	// Inbounds lists the inbound tags whose rows for this recipient were
	// rewritten, in config order.
	Inbounds []string
	// Warnings are non-fatal conditions the operator should see: a config
	// shape that prevented part of the rotation.
	Warnings []string
	// retired holds the credential values this rotation replaced. Nothing
	// here may still appear anywhere in the config afterwards; see
	// assertRetiredAbsent.
	retired []string
}

func (c *credRotation) retire(v string) {
	if v != "" {
		c.retired = append(c.retired, v)
	}
}

// rotateRecipientCreds replaces one named recipient's per-user credentials
// across every inbound that carries a row for them, and touches nothing else.
//
// Per inbound TYPE (not index, not position):
//
//	vless      → users[].uuid, matched on users[].name; plus the paired
//	             REALITY short_id when the inbound has a reality block.
//	             Covers BOTH vless-in (REALITY on 443) and ws-in — one
//	             recipient owns a row in each, keyed by the same UUID,
//	             and rotating only one of them leaves the leaked
//	             credential live on the other tier.
//	hysteria2  → users[].password, matched on users[].name.
//	naive      → users[].password, matched on users[].username. Note the
//	             different key: naive rows spell it `username`, and
//	             matching on `name` there silently rotates nobody.
//	tuic       → users[].uuid AND users[].password, matched on
//	             users[].name. Both halves move together because tuic
//	             authenticates on the pair: rotating the password while
//	             leaving the uuid would keep half of a leaked credential
//	             live, and the uuid is the half that is also the
//	             recipient's stable identifier on this tier. Only
//	             present on a relay provisioned to serve the family.
//
// Explicitly NOT touched:
//
//	the shared ws transport.path — one inbound, one path, every recipient
//	  (see singbox_users.go's package comment). Rotating it to revoke one
//	  person would take the ws tier away from everyone else.
//	tls.server_name / reality.handshake — that is /rotate-tls.
//	reality.private_key — that is a box-wide operation; see the bottom of
//	  this file.
//	every other recipient's rows, in every inbound.
func rotateRecipientCreds(doc map[string]any, name string, fresh userCreds) (*credRotation, error) {
	if name == "" {
		return nil, errors.New("rotateRecipientCreds: empty recipient name")
	}
	res := &credRotation{Creds: fresh}
	res.Creds.Name = name
	// The live shared path, echoed unchanged. The caller hands this straight
	// into a pack, so it must be the path the box actually serves rather than
	// the fresh one mintCreds just generated — the same lesson
	// addUserToSingbox's effectiveWSPath return exists for.
	res.Creds.WSPath = wsInboundPath(doc)
	res.Creds.RealityShortID = ""
	// Same fail-closed contract as /users/provision: the tuic pair is
	// echoed only if this box really rotated a tuic row. A relay whose
	// profile did not enable the family must not hand back credentials
	// the publisher would mint into an undialable route.
	res.Creds.TUICUUID, res.Creds.TUICPassword = "", ""
	// Same for shadowsocks, with one extra rule that is easy to get
	// backwards: the rotation replaces the recipient's uPSK and NEVER the
	// box-wide iPSK. The iPSK is the first half of the password in every
	// pack this relay has ever minted, so re-minting it to revoke one
	// person would take the shadowsocks tier away from everybody — the
	// same reason the shared ws path is left alone. The echoed
	// SSPassword is therefore the LIVE iPSK joined to the FRESH uPSK,
	// assembled from the rewritten document below.
	res.Creds.SSPassword, res.Creds.SSMethod = "", ""
	// Same for anytls, and this is the field that proved the rule
	// necessary rather than tidy. Before the Wave-5 repair pass there
	// was no `case "anytls"` below AND no blanking here, so
	// `res := &credRotation{Creds: fresh}` echoed a password
	// mintCreds had just generated and the box had never stored: the
	// publisher minted a route authenticating with a secret nothing
	// on 8447 would accept, and the SEIZED password stayed live
	// forever because nothing retired it. A rotation that reports
	// success, breaks the route and revokes nothing is strictly worse
	// than one that fails.
	//
	// THE BLANKING IS THE LOAD-BEARING HALF. Every future field added
	// to userCreds repeats this bug unless it is blanked here and set
	// only by the case that really rewrote a row. Blank first, set on
	// success.
	res.Creds.AnyTLSPassword = ""

	for _, raw := range asSlice(doc["inbounds"]) {
		in, _ := raw.(map[string]any)
		if in == nil {
			continue
		}
		typ, _ := in["type"].(string)
		tag, _ := in["tag"].(string)
		if tag == "" {
			tag = typ
		}
		users := asSlice(in["users"])
		switch typ {
		case "vless":
			idxs := matchUserRows(users, "name", name)
			if len(idxs) == 0 {
				continue
			}
			for _, i := range idxs {
				u, _ := users[i].(map[string]any)
				old, _ := u["uuid"].(string)
				res.retire(old)
				u["uuid"] = fresh.VLESSUUID
			}
			if sid, warn := rotateShortIDs(in, idxs, len(users), fresh.RealityShortID); warn != "" {
				res.Warnings = append(res.Warnings, warn)
				res.Creds.RealityShortID = sid
			} else if sid != "" {
				res.Creds.RealityShortID = sid
			}
			res.Inbounds = append(res.Inbounds, tag)
		case "hysteria2":
			idxs := matchUserRows(users, "name", name)
			if len(idxs) == 0 {
				continue
			}
			for _, i := range idxs {
				u, _ := users[i].(map[string]any)
				old, _ := u["password"].(string)
				res.retire(old)
				u["password"] = fresh.Hy2Password
			}
			res.Inbounds = append(res.Inbounds, tag)
		case "tuic":
			idxs := matchUserRows(users, "name", name)
			if len(idxs) == 0 {
				continue
			}
			for _, i := range idxs {
				u, _ := users[i].(map[string]any)
				oldUUID, _ := u["uuid"].(string)
				oldPW, _ := u["password"].(string)
				res.retire(oldUUID)
				res.retire(oldPW)
				u["uuid"] = fresh.TUICUUID
				u["password"] = fresh.TUICPassword
			}
			res.Creds.TUICUUID, res.Creds.TUICPassword = fresh.TUICUUID, fresh.TUICPassword
			res.Inbounds = append(res.Inbounds, tag)
		case "shadowsocks":
			// One row per recipient on the single shared ss-in inbound,
			// matched on `name` (SS rows spell it `name`, unlike naive's
			// `username` below). Only users[].password — the uPSK — moves;
			// inbound.password — the iPSK — is deliberately untouched.
			idxs := matchUserRows(users, "name", name)
			if len(idxs) == 0 {
				continue
			}
			for _, i := range idxs {
				u, _ := users[i].(map[string]any)
				old, _ := u["password"].(string)
				res.retire(old)
				u["password"] = fresh.SSUserPSK
			}
			// Assembled from THIS document after the write, so the echoed
			// value is the live iPSK and not something remembered.
			if pw := ssClientPassword(doc, name); pw != "" {
				res.Creds.SSPassword, res.Creds.SSMethod = pw, ssMethod
			}
			res.Inbounds = append(res.Inbounds, tag)
		case "anytls":
			// One row per recipient on the single shared anytls-in
			// inbound, matched on `name` (anytls rows spell it `name`,
			// like SS and unlike naive's `username` below). The
			// password is the whole credential — anytls hashes it into
			// the session key, there is no second half — so replacing
			// it is the entire rotation for this family, and the old
			// value must be retired or the seized credential keeps
			// working on 8447.
			//
			// The inbound's `padding_scheme` is deliberately NOT
			// touched: it is per-relay, adopted by the client over the
			// wire, and shared by every recipient. Re-generating it to
			// revoke one person would re-shape the traffic of everyone
			// on this relay, the same reason the shared ws path is left
			// alone.
			idxs := matchUserRows(users, "name", name)
			if len(idxs) == 0 {
				continue
			}
			for _, i := range idxs {
				u, _ := users[i].(map[string]any)
				old, _ := u["password"].(string)
				res.retire(old)
				u["password"] = fresh.AnyTLSPassword
			}
			res.Creds.AnyTLSPassword = fresh.AnyTLSPassword
			res.Inbounds = append(res.Inbounds, tag)
		case "naive":
			// `username`, not `name`. sing-box's naive inbound uses a
			// different user shape; matching the wrong key here is a
			// rotation that reports success and revokes nothing on 8444.
			idxs := matchUserRows(users, "username", name)
			if len(idxs) == 0 {
				continue
			}
			for _, i := range idxs {
				u, _ := users[i].(map[string]any)
				old, _ := u["password"].(string)
				res.retire(old)
				u["password"] = fresh.NaivePassword
			}
			res.Inbounds = append(res.Inbounds, tag)
		}
	}
	if len(res.Inbounds) == 0 {
		return nil, errRecipientNotFound
	}
	return res, nil
}

// matchUserRows returns the indices of every user row whose `key` field
// equals name. Every match is rewritten, not just the first: a config that
// somehow carries a duplicate row would otherwise keep a live copy of the
// credential the caller believes they just revoked.
func matchUserRows(users []any, key, name string) []int {
	var out []int
	for i, raw := range users {
		u, _ := raw.(map[string]any)
		if u == nil {
			continue
		}
		if n, _ := u[key].(string); n == name {
			out = append(out, i)
		}
	}
	return out
}

// rotateShortIDs replaces the REALITY short_id entries paired with the given
// user rows, and returns the short_id the box now accepts for that recipient
// plus a non-empty warning when it could not be rotated.
//
// Index correspondence is the whole mechanism, exactly as in
// appendVLESSUser/removeVLESSUser: users[i] owns short_id[i] because they are
// appended together in one call. When the two lists are the same length that
// pairing holds and we rewrite precisely this recipient's entries.
//
// When they are NOT the same length (a hand-edited config, or a box that
// predates the paired append) there is no way to tell whose entry is whose.
// Overwriting one would revoke a bystander — the exact bug removeVLESSUser
// was fixed for — and handing back an EXISTING entry (sids[0], which this
// used to do) is the same mistake one step removed: the rotated recipient
// would pin a value whose lifetime belongs to somebody else, so a later
// revocation of that somebody else silently takes this recipient's
// vless-reality tier away with no event linking the two.
//
// So the misaligned case APPENDS the fresh entry instead. It disturbs no
// existing entry, so no other recipient can be broken by it, and the value
// returned is unambiguously this recipient's. That works because short_id
// is a set on the wire, not a per-user binding: a REALITY server accepts
// any entry present in short_id[], from anyone. The warning still goes out,
// because a list that cannot be attributed is a config a human should look
// at — and because the appended entry is as unattributable as the rest to
// the next code that walks it.
func rotateShortIDs(in map[string]any, idxs []int, nUsers int, fresh string) (string, string) {
	tlsBlock, _ := in["tls"].(map[string]any)
	if tlsBlock == nil {
		return "", ""
	}
	reality, _ := tlsBlock["reality"].(map[string]any)
	if reality == nil {
		return "", ""
	}
	sids := asSlice(reality["short_id"])
	if len(sids) == 0 {
		return "", ""
	}
	if len(sids) != nUsers {
		if fresh == "" {
			return "", fmt.Sprintf("reality.short_id has %d entries for %d users; not index-aligned, and no replacement short_id was minted, so it was left alone (the UUID was rotated)", len(sids), nUsers)
		}
		reality["short_id"] = append(sids, fresh)
		return fresh, fmt.Sprintf("reality.short_id has %d entries for %d users; not index-aligned, so no existing entry could be attributed — this recipient's new short_id was ADDED to the list and the others were left untouched. The surplus entries should be cleaned up by hand", len(sids), nUsers)
	}
	for _, i := range idxs {
		sids[i] = fresh
	}
	reality["short_id"] = sids
	return fresh, ""
}

// assertRetiredAbsent is the last line of defence before the config is
// committed: every value the rotation claims to have replaced must be gone
// from the document entirely. If one survives — a fifth inbound this code
// does not know about, a duplicated row, a shape change in sing-box — the
// rotation is abandoned with the live config untouched, because a revocation
// that silently leaves the old credential accepted is worse than a failed
// one. The operator retries; they do not get told a leak was closed when it
// was not.
//
// Structural, not a substring scan of the marshalled bytes: "uuid-1" is a
// substring of "uuid-12", and a false positive here fails a correct rotation.
//
// The offending value is never echoed — the error reaches an HTTP response,
// and a retired credential is still a credential.
func assertRetiredAbsent(doc map[string]any, retired []string) error {
	for _, v := range retired {
		if v == "" {
			continue
		}
		if docContainsString(doc, v) {
			return errors.New("rotation incomplete: a retired credential is still present in the rewritten config; live config left untouched")
		}
	}
	return nil
}

func docContainsString(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case map[string]any:
		for _, vv := range t {
			if docContainsString(vv, want) {
				return true
			}
		}
	case []any:
		for _, vv := range t {
			if docContainsString(vv, want) {
				return true
			}
		}
	}
	return false
}

// --- box-wide TLS / cover-identity rotation ------------------------------

// tlsRotation reports what the box ACTUALLY advertises after the call, read
// back out of the rewritten document rather than echoed from the request.
//
// Changed is the honest part. `/rotate-tls` accepts an empty body (the pinned
// contract's `POST /rotate-tls {}`), and an empty body cannot mean "invent a
// new cover host": a plausible cover identity depends on the relay's provider
// and region, which is publisher knowledge, and a fleet-wide constant baked
// into this binary is one free string match away from burning every relay at
// once. So an empty body rotates only what the box legitimately owns — the
// shared ws path — and Changed says exactly that, so the caller can tell the
// operator "the cover host was NOT replaced; supply one" instead of showing a
// green tick.
type tlsRotation struct {
	SNI       string   // effective tls.server_name
	Handshake string   // effective reality.handshake as host:port
	WSPath    string   // effective shared ws transport.path ("" if no ws inbound)
	Changed   []string // subset of {"cover_sni","reality_handshake","ws_path"}
}

// rewriteSingboxTLS applies a cover-identity rotation and returns what the
// box now serves.
//
// It does NOT touch user credentials and it does NOT touch reality.private_key
// — that is the whole point of the split. The only keys it may write are
// tls.server_name, reality.handshake.{server,server_port} and the shared
// ws transport.path.
//
// Two request shapes:
//
//	new_sni set   → apply exactly that (dests[0] optionally moves the
//	                handshake PORT; its host is validated by the handler to
//	                equal new_sni). ws path moves only if new_ws_path is
//	                given, because "apply exactly this" must not have side
//	                effects the caller did not ask for.
//	body empty    → rotate what the box owns: mint a new shared ws path, and
//	                repair any drift between server_name and
//	                reality.handshake.server. The cover host is left alone.
//
// The returned rollback closure restores the pre-rotation config; the
// caller must hand it to applyReload so a failed activation cannot leave
// a cover identity on disk that nothing outside the box knows about.
func (s *server) rewriteSingboxTLS(path string, req rotateTLSReq) (tlsRotation, func(), error) {
	var out tlsRotation
	doc, err := loadSingboxDoc(path)
	if err != nil {
		return out, nil, err
	}

	beforeSNI := coverSNI(doc)
	beforeHost, beforePort := realityHandshake(doc)
	beforeWS := wsInboundPath(doc)

	if req.NewSNI != "" {
		if err := surgicalSetSNI(doc, req.NewSNI, req.NewDests); err != nil {
			return out, nil, err
		}
	} else {
		// No new cover host: still make the two names agree. A box whose
		// server_name and handshake.server have drifted apart is the
		// IP-to-SNI mismatch REALITY exists to prevent, and this is the one
		// operation that is allowed to fix it in place.
		repairRealityHandshake(doc)
	}

	wsPath := req.NewWSPath
	if wsPath == "" && req.NewSNI == "" {
		if wsPath, err = rotatedWSPath(beforeWS); err != nil {
			return out, nil, err
		}
	}
	if wsPath != "" {
		if err := surgicalSetWSPath(doc, wsPath); err != nil {
			return out, nil, err
		}
	}

	out.SNI = coverSNI(doc)
	afterHost, afterPort := realityHandshake(doc)
	out.Handshake = net.JoinHostPort(afterHost, strconv.Itoa(afterPort))
	out.WSPath = wsInboundPath(doc)
	if out.SNI != beforeSNI {
		out.Changed = append(out.Changed, "cover_sni")
	}
	if afterHost != beforeHost || afterPort != beforePort {
		out.Changed = append(out.Changed, "reality_handshake")
	}
	if out.WSPath != beforeWS {
		out.Changed = append(out.Changed, "ws_path")
	}
	if len(out.Changed) == 0 {
		return out, nil, errNothingToRotate
	}
	// commitSingboxDoc proves sing-box will load the result BEFORE it
	// replaces the live file. Requirement, not belt-and-braces: two shipped
	// bugs in this service each produced a config the strict 1.13 parser
	// FATALs on, on a box with no SSH path back in.
	rollback, err := s.commitSingboxDoc(path, doc)
	if err != nil {
		return out, nil, err
	}
	return out, rollback, nil
}

// realityHandshake returns the box's REALITY handshake dest, from the first
// vless-family inbound that has a reality block. Selected by type and looped,
// never indexed: hy2-in can and does land at inbounds[0] on some provisioning
// orders.
func realityHandshake(doc map[string]any) (string, int) {
	for _, in := range vlessFamilyInbounds(doc) {
		tlsBlock, _ := in["tls"].(map[string]any)
		if tlsBlock == nil {
			continue
		}
		reality, _ := tlsBlock["reality"].(map[string]any)
		if reality == nil {
			continue
		}
		hs, _ := reality["handshake"].(map[string]any)
		if hs == nil {
			return "", 0
		}
		host, _ := hs["server"].(string)
		port := 0
		// A freshly-decoded config yields float64; a block this process just
		// wrote yields int. Both spellings occur within a single request.
		switch v := hs["server_port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		}
		return host, port
	}
	return "", 0
}

// repairRealityHandshake forces reality.handshake.server to equal
// tls.server_name on every vless-family inbound that has both, and drops the
// legacy `reality.server_names` key an older rotation may have left behind
// (not a field in sing-box 1.13 — the config does not parse with it present).
// Reports whether anything moved.
func repairRealityHandshake(doc map[string]any) bool {
	changed := false
	for _, in := range vlessFamilyInbounds(doc) {
		tlsBlock, _ := in["tls"].(map[string]any)
		if tlsBlock == nil {
			continue
		}
		sni, _ := tlsBlock["server_name"].(string)
		if sni == "" {
			continue
		}
		reality, _ := tlsBlock["reality"].(map[string]any)
		if reality == nil {
			continue
		}
		if _, present := reality["server_names"]; present {
			delete(reality, "server_names")
			changed = true
		}
		hs, _ := reality["handshake"].(map[string]any)
		if hs == nil {
			hs = map[string]any{}
			reality["handshake"] = hs
		}
		if host, _ := hs["server"].(string); host != sni {
			hs["server"] = sni
			changed = true
		}
		if _, present := hs["server_port"]; !present {
			hs["server_port"] = 443
			changed = true
		}
	}
	return changed
}

// rotatedWSPath mints a replacement for the shared ws path, preserving the
// existing path's first segment so the shape on the wire is indistinguishable
// from a provisioned one (`/r0/<8 hex>` — see mintCreds). Returns "" when the
// box has no ws inbound yet, which is not an error: ws-in is created lazily by
// the first recipient.
func rotatedWSPath(existing string) (string, error) {
	if existing == "" {
		return "", nil
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	prefix := strings.SplitN(strings.Trim(existing, "/"), "/", 2)[0]
	if prefix == "" {
		prefix = "r0"
	}
	return "/" + prefix + "/" + hex.EncodeToString(b[:]), nil
}

// --- the third operation, deliberately not implemented here --------------
//
// BOX REALITY KEYPAIR ROTATION is a third operation with a third blast
// radius, and it is NOT reachable from either endpoint above — not as a
// flag, not as a side effect of an empty body, not at all. Regenerating
// reality.private_key invalidates the public key pinned in every pack this
// box ever emitted, so it is only safe in company with a redistribution path
// (Step 8, freshness delivery). Until that exists, the operation's honest
// description is "disconnect everyone, permanently, unless you can hand each
// recipient a file", which is not something any button should do as a
// side effect of the word "rotate".
//
// It needs its own endpoint with its own explicit confirmation, and that
// endpoint would be the EIGHTH route. specs/daal-relay-mgmt-v1.md §4 pins the
// surface at seven and states that an eighth requires a supplement amendment;
// TestExactlyNRoutes enforces it. Adding it silently here would be the
// process equivalent of the bug this file fixes, so it is left out and
// written down instead.
//
// When it lands it must, at minimum:
//   - take an explicit confirmation token in the body (not a boolean — a
//     boolean is what a retry loop sends by accident);
//   - write BOTH halves: /etc/daal/reality.pub as well as the config's
//     private_key. The public file is what /users/provision reads to tell
//     the publisher which key to pin, so a rotation that skips it makes
//     every subsequently minted pack unusable;
//   - `restart` rather than `reload` — the keypair is inbound-construction
//     material, not user-table state;
//   - be gated in the UI behind the redistribution path actually being
//     configured for that relay.
