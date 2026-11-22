package gittag

import (
	"bytes"
	"context"
	"net/http"
	"sort"
	"strings"
)

// Token check verdicts, in the style of the Cloudflare key check
// (publisher/deploy/cloudflare/token_check.go). Only VerdictOK and
// VerdictOKBroad may be stored (TokenCheck.Usable).
const (
	VerdictOK                = "ok"
	VerdictOKBroad           = "ok_broad"           // works; Extra names what it can do beyond what Daal needs
	VerdictInvalid           = "invalid"            // GitHub does not accept it, or it is not a person's token
	VerdictMissingPermission = "missing_permission" // Missing names what to add
	VerdictOwnerMismatch     = "owner_mismatch"     // works, but belongs to another account than the one asked for
)

// Token kinds.
const (
	TokenClassic     = "classic"      // ghp_…: scopes are listed in X-OAuth-Scopes
	TokenFineGrained = "fine_grained" // github_pat_…: GitHub lists no permissions
	TokenOther       = "other"        // anything else GitHub accepted
)

// What Daal needs, by token kind.
const (
	// ScopePublicRepo is the classic scope that creates a public
	// repository and writes to it. "repo" also does (and more).
	ScopePublicRepo = "public_repo"
	// PermAdministration and PermContents are the fine-grained
	// permissions: Administration to create the repository, Contents
	// to write files and tags. Repository access must be "All
	// repositories" (a new repository is not in a fixed list).
	PermAdministration = "Administration: Read and write"
	PermContents       = "Contents: Read and write"
)

// TokenCheck is what `daal-deploy note-gittag check` prints. It names
// no secret.
type TokenCheck struct {
	Verdict   string `json:"verdict"`
	Login     string `json:"login,omitempty"`
	TokenKind string `json:"token_kind,omitempty"`
	// Missing: what to grant (missing_permission).
	Missing []string `json:"missing,omitempty"`
	// Extra: what the token can do beyond what Daal needs (ok_broad).
	Extra []string `json:"extra,omitempty"`
	// Unproven: what one read cannot show; the first publish shows it,
	// and a refusal there names the permission.
	Unproven []string `json:"unproven,omitempty"`
	// ExpiresAt is GitHub's expiry of the token, as GitHub writes it
	// ("2026-12-01 00:00:00 UTC"); empty when it never expires.
	ExpiresAt string `json:"expires_at,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

// Usable says whether the token may be kept and used.
func (c TokenCheck) Usable() bool {
	return c.Verdict == VerdictOK || c.Verdict == VerdictOKBroad
}

// classicScopesEnough are the classic scopes each of which alone is enough.
var classicScopesEnough = map[string]bool{ScopePublicRepo: true, "repo": true}

// CheckToken asks GitHub who the token is, in ONE call (GET /user), and
// decides whether it can create a public repository and write to it.
// wantOwner, when non-empty, is the account the repository is to live
// under; in this wave it must be the token's own account.
//
// A classic token lists its scopes, so the answer is complete. A
// fine-grained token lists nothing: the verdict is ok with the two
// permissions under Unproven, and Publish names the one GitHub refuses.
//
// Errors are only for no usable answer (network, rate limit, 5xx); a
// token GitHub refuses is VerdictInvalid with a nil error.
func (c *Client) CheckToken(ctx context.Context, wantOwner string) (TokenCheck, error) {
	out := TokenCheck{TokenKind: tokenKind(c.token)}
	var u struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	}
	status, h, err := c.call(ctx, "check the token", http.MethodGet, "/user", nil, &u, "")
	if err != nil {
		switch {
		case IsKind(err, KindInvalidToken):
			out.Verdict = VerdictInvalid
			out.Notes = "GitHub does not accept this token"
			return out, nil
		case IsKind(err, KindMissingPermission):
			// /user answers any personal token; a 403 that is not a
			// rate limit is a token of an app or an installation.
			out.Verdict = VerdictInvalid
			out.Notes = "this is not a personal access token"
			return out, nil
		}
		return out, err
	}
	_ = status
	if u.Login == "" {
		return out, &APIError{Op: "check the token", Status: status, Kind: KindGitHub}
	}
	out.Login = u.Login
	out.ExpiresAt = strings.TrimSpace(h.Get("GitHub-Authentication-Token-Expiration"))
	if u.Type != "" && u.Type != "User" {
		out.Verdict = VerdictInvalid
		out.Notes = "the token belongs to a " + u.Type + ", not a person's account"
		return out, nil
	}

	scopes, listed := h["X-Oauth-Scopes"]
	if listed {
		if out.TokenKind == TokenOther {
			out.TokenKind = TokenClassic
		}
		have := parseScopes(strings.Join(scopes, ","))
		enough := false
		for s := range have {
			if classicScopesEnough[s] {
				enough = true
			}
		}
		if !enough {
			out.Missing = []string{ScopePublicRepo}
		}
		for s := range have {
			switch {
			case s == ScopePublicRepo:
			case s == "repo":
				out.Extra = append(out.Extra, "repo (private repositories too; public_repo is enough)")
			default:
				out.Extra = append(out.Extra, s)
			}
		}
		sort.Strings(out.Extra)
	} else {
		if out.TokenKind == TokenOther {
			out.TokenKind = TokenFineGrained
		}
		out.Unproven = []string{
			PermAdministration + " (to create the repository)",
			PermContents,
			"Repository access: All repositories",
		}
	}

	switch {
	case wantOwner != "" && !strings.EqualFold(wantOwner, u.Login):
		out.Verdict = VerdictOwnerMismatch
		out.Notes = "the token belongs to another GitHub account"
	case len(out.Missing) > 0:
		out.Verdict = VerdictMissingPermission
	case len(out.Extra) > 0:
		out.Verdict = VerdictOKBroad
	default:
		out.Verdict = VerdictOK
	}
	return out, nil
}

func parseScopes(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

func tokenKind(t []byte) string {
	switch {
	case bytes.HasPrefix(t, []byte("github_pat_")):
		return TokenFineGrained
	case bytes.HasPrefix(t, []byte("ghp_")):
		return TokenClassic
	}
	return TokenOther
}
