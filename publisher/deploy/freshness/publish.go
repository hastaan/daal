package freshness

// publish.go uploads one signed document to every mirror.
//
// The rule this file enforces is the publish-time half of the
// no-single-URL contract: a pack promises N endpoints, so a
// publish that lands on one of them has quietly downgraded every
// recipient to a single point of failure while reporting success.
// PublishAll therefore treats "fewer than MinMirrors targets
// accepted the write" as an error, and returns the per-target
// detail alongside it so the operator can see WHICH provider is
// refusing rather than being told "publish failed".

import (
	"context"
	"errors"
	"fmt"
)

// ErrPublishDegraded is returned when fewer than MinMirrors
// targets accepted the document. The per-target results are still
// returned: the document IS live wherever it succeeded, and the
// operator needs to know that as much as they need to know about
// the failure.
var ErrPublishDegraded = errors.New("freshness: publish landed on fewer than the required number of mirrors")

// Target pairs a provider label with its uploader. The label must
// match the one used in the pack's MirrorSet, or the recipient
// will be polling a URL nobody is writing to.
type Target struct {
	Provider Provider
	Backend  Backend
}

// PublishResult is one target's outcome.
type PublishResult struct {
	Provider Provider `json:"provider"`
	URL      string   `json:"url"`
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
}

// PublishAll uploads body to every target.
//
// Every target is attempted even after one fails — a partial
// outage on R2 must not stop the GitHub Pages copy from going up,
// because the copy that goes up is the one a censored recipient
// will reach.
//
// Ordering note: the write order is the caller's slice order and
// is NOT a ranking. Mirrors are inconsistent by construction (GH
// Pages lags its API write by a build cycle), so a recipient will
// routinely see two different documents from two mirrors within
// the same minute. That is safe precisely because the recipient
// keeps a sequence high-water mark: a lagging mirror serves an
// older sequence, which is accepted-but-ignored rather than
// treated as an instruction to roll back.
func PublishAll(ctx context.Context, body []byte, targets []Target) ([]PublishResult, error) {
	if len(body) == 0 {
		return nil, errors.New("freshness: empty document body")
	}
	if len(targets) < MinMirrors {
		return nil, fmt.Errorf("%w: %d target(s) configured, need %d",
			ErrTooFewMirrors, len(targets), MinMirrors)
	}
	seen := map[Provider]bool{}
	results := make([]PublishResult, 0, len(targets))
	ok := 0
	for _, t := range targets {
		if t.Backend == nil {
			return nil, fmt.Errorf("freshness: target %q has no backend", t.Provider)
		}
		if seen[t.Provider] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateProvider, t.Provider)
		}
		seen[t.Provider] = true
		res := PublishResult{Provider: t.Provider, URL: t.Backend.PublicURL()}
		if err := t.Backend.Put(ctx, body); err != nil {
			// The error string may carry a provider response body.
			// It is shown to the operator on their own machine and
			// never leaves it; the URL is not logged anywhere else.
			res.Error = err.Error()
		} else {
			res.OK = true
			ok++
		}
		results = append(results, res)
	}
	if ok < MinMirrors {
		return results, fmt.Errorf("%w: %d of %d succeeded", ErrPublishDegraded, ok, len(targets))
	}
	return results, nil
}
