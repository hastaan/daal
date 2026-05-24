// FRP-14: per-recipient credentials API.
//
// Adds three routes to the in-box mgmt plane:
//
//	POST /users/provision  — append a fresh per-recipient user row
//	                          to every sing-box inbound; return creds.
//	POST /users/revoke     — remove a user row, run kick wrapper,
//	                          reload sing-box.
//	GET  /users/list       — list active user names.
//
// See specs/per-recipient-credentials-v1.md for the wire format
// and on-box invariants. The surgical sing-box rewriter lives in
// singbox_users.go to keep the routing surface here readable.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// MaxRecipientsPerServer is the hard cap from FRP-14 invariant 7.
// Each recipient adds one row to the VLESS / Hy2 / Naive inbounds
// and one full WS-TLS inbound block. The cap bounds reload time and
// config size.
const MaxRecipientsPerServer = 128

// nameRegex matches the recipient names the wizard emits:
// `r<digits>`, 1..12 digits, e.g. "r17", "r420". The on-box
// service does not interpret the digits; they map back to the
// wizard's `recipients.id` PK.
var nameRegex = regexp.MustCompile(`^r[0-9]{1,12}$`)

// userCreds is the JSON returned by /users/provision and is also
// the shape persisted in the publisher app's operator_recipients
// table. Fields match per-recipient-credentials-v1.md §3.1.
type userCreds struct {
	Name              string `json:"name"`
	VLESSUUID         string `json:"vless_uuid"`
	RealityShortID    string `json:"reality_short_id"` // 8 hex chars
	Hy2Password       string `json:"hy2_password"`     // 22 b64-url chars
	NaivePassword     string `json:"naive_password"`   // 22 b64-url chars
	WSPath            string `json:"ws_path"`          // /r<id>/<8 hex>
	ProvisionedAtUnix int64  `json:"provisioned_at_unix"`
}

type userMeta struct {
	Name              string `json:"name"`
	ProvisionedAtUnix int64  `json:"provisioned_at_unix"`
}

type provisionReq struct {
	Name string `json:"name"`
}

type revokeReq struct {
	Name string `json:"name"`
}

type listResp struct {
	Users []userMeta `json:"users"`
}

func (s *server) handleUsersProvision(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.usersProvCnt.Add(1)
	var req provisionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !nameRegex.MatchString(req.Name) {
		http.Error(w, "name must match r[0-9]{1,12}", http.StatusBadRequest)
		return
	}

	count, err := countUsers(s.singboxConfig)
	if err != nil {
		http.Error(w, "count users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if count >= MaxRecipientsPerServer {
		http.Error(w, fmt.Sprintf("max recipients (%d) reached on this server", MaxRecipientsPerServer), http.StatusConflict)
		return
	}
	exists, err := userExists(s.singboxConfig, req.Name)
	if err != nil {
		http.Error(w, "check duplicate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, fmt.Sprintf("user %q already exists", req.Name), http.StatusConflict)
		return
	}

	creds, err := mintCreds(req.Name, s.now().Unix())
	if err != nil {
		http.Error(w, "mint creds: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := addUserToSingbox(s.singboxConfig, creds); err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.singboxControl("reload"); err != nil {
		http.Error(w, "singbox reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

func (s *server) handleUsersRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.usersRevokeCnt.Add(1)
	var req revokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !nameRegex.MatchString(req.Name) {
		http.Error(w, "name must match r[0-9]{1,12}", http.StatusBadRequest)
		return
	}
	removed, err := removeUserFromSingbox(s.singboxConfig, req.Name)
	if err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, fmt.Sprintf("user %q not found", req.Name), http.StatusNotFound)
		return
	}
	// Force-kick first (SIGUSR2 + reload via the wrapper script),
	// then a plain reload to settle config. Both are best-effort:
	// even if the wrapper fails (e.g., sing-box version doesn't
	// honor SIGUSR2 on this build), the user row is gone from the
	// config and new connections fail auth.
	if err := s.singboxKick(); err != nil {
		// Soft-fail: the revoke succeeded at the config level.
		// Log but don't bubble — old-version-singbox boxes still
		// get correct semantics on next idle/reconnect.
		// Caller can still inspect counts.
	}
	if err := s.singboxControl("reload"); err != nil {
		http.Error(w, "singbox reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{
		"revoked_at_unix": s.now().Unix(),
	})
}

func (s *server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.usersListCnt.Add(1)
	users, err := listUsers(s.singboxConfig)
	if err != nil {
		http.Error(w, "list users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listResp{Users: users})
}

// mintCreds generates fresh per-recipient credentials. All fields
// use crypto/rand.
func mintCreds(name string, nowUnix int64) (userCreds, error) {
	uuid, err := genUUID()
	if err != nil {
		return userCreds{}, err
	}
	var shortID [4]byte
	if _, err := rand.Read(shortID[:]); err != nil {
		return userCreds{}, err
	}
	var hy2Raw, naiveRaw, wsPathRaw [16]byte
	if _, err := rand.Read(hy2Raw[:]); err != nil {
		return userCreds{}, err
	}
	if _, err := rand.Read(naiveRaw[:]); err != nil {
		return userCreds{}, err
	}
	if _, err := rand.Read(wsPathRaw[:]); err != nil {
		return userCreds{}, err
	}
	// WS path uses 4 random bytes hex-encoded (8 chars), so it
	// stays URL-safe and short.
	return userCreds{
		Name:              name,
		VLESSUUID:         uuid,
		RealityShortID:    hex.EncodeToString(shortID[:]),
		Hy2Password:       base64.RawURLEncoding.EncodeToString(hy2Raw[:]),
		NaivePassword:     base64.RawURLEncoding.EncodeToString(naiveRaw[:]),
		WSPath:            fmt.Sprintf("/%s/%s", name, hex.EncodeToString(wsPathRaw[:4])),
		ProvisionedAtUnix: nowUnix,
	}, nil
}
