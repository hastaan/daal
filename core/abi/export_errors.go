package abi

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
)

// Failed engine calls, made diagnosable.
//
// Every C-ABI wrapper (core/abi/*_export.go) used to turn a Go error
// into a bare -1 and drop the error. The shell above could then say
// only "engine call returned -1", the page above that showed "unknown",
// and the device log had nothing: on the first real-phone pass three
// screens failed and no layer could say why.
//
// A wrapper that is about to return a negative code now goes through
// exportFail / exportFailCode (abi_export.go), which hand the error to
// noteExportError here. That does two things with a SCRUBBED one-line
// account of it:
//
//   - writes "engine_<name>: <text>" to the engine log (logcat, tag
//     daalengine, on Android);
//   - keeps it in a ring of the last recentErrorsMax failures, which
//     ExportDiagnostics serves as `recent_errors`.
//
// What the text may contain. Nothing here is trusted to be free of
// secrets: an error can quote a URL, a server address, a file a
// credential was read from. So:
//
//   - a failed engine_set_route is reduced to the route id and a closed
//     code — the refusal code, or the failure category — and NONE of its
//     error text (routeErrorSummary);
//   - every other error's text goes through engine.Scrub, which removes
//     URLs, addresses, host names, UUIDs, credential-looking assignments
//     and long tokens, and bounds the length.
//
// The ring is memory only: it is never written to the store and is
// gone when the process ends.

const recentErrorsMax = 50

// RecentError is one entry of `recent_errors`.
type RecentError struct {
	// Time of the most recent occurrence, UTC, to the second.
	Time string `json:"time"`
	// Call is the C-ABI function that failed, e.g. "engine_set_route".
	Call string `json:"call"`
	// Text is the scrubbed account of the failure.
	Text string `json:"text"`
	// Count is how many times this same call has failed with this same
	// text (a poll that fails every half second is one entry).
	Count int `json:"count"`
}

var (
	recentErrMu  sync.Mutex
	recentErrBuf []RecentError
)

// noteExportError records that the export wrapper `call` is failing
// with err. Safe before Init and after Shutdown.
func noteExportError(call string, err error) {
	if err == nil {
		return
	}
	if secretHandlingCalls[call] {
		noteExportFailure(call, "failed (text withheld: this call is handed secrets) class="+errClass(err))
		return
	}
	noteExportFailure(call, engine.Scrub(errorText(err)))
}

// secretHandlingCalls are the exports whose ARGUMENTS are secrets — a
// PIN, a share URI with credentials in it, a pack, proxy credentials, a
// subscription URL. An error from one of them may quote its input in a
// shape no pattern recognises (half a malformed URI, a few bytes of a
// pack), so none of the error text is kept: only the Go type of the
// innermost error.
var secretHandlingCalls = map[string]bool{
	"engine_unlock_secrets":       true,
	"engine_import_sbp":           true,
	"engine_resolve_trust_prompt": true,
	"engine_uri_detect":           true,
	"engine_uri_import":           true,
	"engine_share_begin":          true,
	"engine_share_pull":           true,
	"engine_share_pull_url":       true,
	"engine_fountain_feed_frame":  true,
	"engine_fountain_next_frame":  true,
	"engine_set_tunnel_socks":     true,
	"engine_subscription_add":     true,
}

// errClass is the Go type of the innermost error in err's chain.
func errClass(err error) string {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return fmt.Sprintf("%T", err)
		}
		err = inner
	}
}

// noteRouteError is noteExportError for engine_set_route: the route id
// and a closed code only.
func noteRouteError(call, routeID string, err error) {
	if err == nil {
		return
	}
	noteExportFailure(call, "route="+engine.LogID(routeID)+" "+routeErrorSummary(err))
}

// noteExportFailure records an already-safe text for call. The text
// still passes through the scrubber on its way to the log.
func noteExportFailure(call, text string) {
	text = engine.Scrub(text)
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	recentErrMu.Lock()
	count := 1
	// The same failure of the same call is ONE entry wherever it sits
	// in the ring, moved to the end: two polls that fail in turn must
	// not push everything else out between them.
	found := -1
	for i := len(recentErrBuf) - 1; i >= 0; i-- {
		if recentErrBuf[i].Call == call && recentErrBuf[i].Text == text {
			found = i
			break
		}
	}
	if found >= 0 {
		e := recentErrBuf[found]
		e.Count++
		e.Time = now
		count = e.Count
		recentErrBuf = append(append(recentErrBuf[:found:found], recentErrBuf[found+1:]...), e)
	} else {
		recentErrBuf = append(recentErrBuf, RecentError{Time: now, Call: call, Text: text, Count: 1})
		if len(recentErrBuf) > recentErrorsMax {
			recentErrBuf = append([]RecentError(nil), recentErrBuf[len(recentErrBuf)-recentErrorsMax:]...)
		}
	}
	recentErrMu.Unlock()
	// A call that fails on every poll must not flood the log: the
	// first failure, then every time the run doubles.
	if count&(count-1) == 0 {
		line := call + ": " + text
		if count > 1 {
			line += fmt.Sprintf(" (x%d)", count)
		}
		engine.LogError(line)
	}
}

// recentErrors returns a copy of the ring, oldest first. Never nil, so
// the diagnostics field is always an array.
func recentErrors() []RecentError {
	recentErrMu.Lock()
	defer recentErrMu.Unlock()
	out := make([]RecentError, len(recentErrBuf))
	copy(out, recentErrBuf)
	return out
}

func resetRecentErrorsForTest() {
	recentErrMu.Lock()
	recentErrBuf = nil
	recentErrMu.Unlock()
}

// errorText is err's message, or the panic value's for a recovered
// panic handed in as an error.
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// routeErrorSummary reduces the error of a failed SetRoute to a closed
// vocabulary. No part of the error's text is used: a refusal names the
// reason by code, and a failure's text can carry the relay's address.
func routeErrorSummary(err error) string {
	var (
		refusal *routeRefusal
		failure *routeFailure
	)
	switch {
	case errors.Is(err, ErrNoDataPlane):
		return "result=no_data_plane"
	case errors.Is(err, ErrConnectCancelled):
		return "result=cancelled"
	case errors.As(err, &refusal):
		return "result=refused code=" + refusal.code
	case errors.As(err, &failure):
		return "result=not_carrying category=" + string(failure.category)
	}
	// The engine instance could not be started at all. The category is
	// the same closed classification the route's failure row gets.
	return "result=start_failed category=" + string(diagnostics.Classify(err.Error()))
}
