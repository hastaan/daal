package provider

import (
	"context"
	"regexp"
	"strings"
)

// Server states a ServerStater reports (relay-health, contract D3).
const (
	ServerRunning  = "running"
	ServerStopped  = "stopped"
	ServerStarting = "starting"
	ServerMissing  = "missing"
)

// ServerStater is implemented by adapters that can say whether the
// record's server exists at the provider and is switched on. Read-only.
// An adapter without it (stark) leaves the health check's server leg
// "not_checked".
type ServerStater interface {
	// ServerState returns running | stopped | starting | missing. An
	// error means the provider could not be asked; it never means
	// "missing".
	ServerState(ctx context.Context, rec *OperatorRecord) (string, error)
}

// commandSegment matches the parts of a warning that are a command for a
// person at a terminal: anything in backticks, a curl invocation, an
// environment variable, or a "daal-deploy <verb>" mention.
var commandSegment = regexp.MustCompile("`|\\bcurl\\s|\\$[A-Z_]{3,}|daal-deploy\\s+[a-z]")

// sentenceSep and clauseSep split a warning the way this package's
// adapters write them: sentences joined by ". ", and inside a sentence a
// statement followed by advice after " — " or "; ".
var (
	sentenceSep = regexp.MustCompile(`\. `)
	clauseSep   = regexp.MustCompile(`( — |; )`)
)

// PlainWarning removes every command a person would have to type from
// w, keeping the statement of what happened. The app shows provider
// warnings only under Details, but `decommission --release-addresses`
// promises that none of them contains a command line at all — the
// person has a phone, not a terminal.
//
// Rule, per sentence: a sentence without a command is kept whole. A
// sentence with one keeps only the clauses BEFORE the first clause that
// carries the command — unless it is advice from its first word ("To
// see what is left, run ..."), which goes entirely. Returns "" when
// nothing is left.
func PlainWarning(w string) string {
	var kept []string
	for _, sentence := range sentenceSep.Split(w, -1) {
		if !commandSegment.MatchString(sentence) {
			if strings.TrimSpace(sentence) != "" {
				kept = append(kept, sentence)
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(sentence), "To ") {
			continue
		}
		cut := len(sentence)
		for _, m := range clauseSep.FindAllStringIndex(sentence, -1) {
			if commandSegment.MatchString(sentence[m[1]:]) && !commandSegment.MatchString(sentence[:m[0]]) {
				cut = m[0]
			}
		}
		head := sentence[:cut]
		if cut == len(sentence) || commandSegment.MatchString(head) || strings.TrimSpace(head) == "" {
			continue
		}
		kept = append(kept, head)
	}
	out := strings.TrimSpace(strings.Join(kept, ". "))
	return strings.TrimRight(out, " —;")
}

// PlainWarnings applies PlainWarning to each warning and drops those left
// empty. Never returns nil.
func PlainWarnings(ws []string) []string {
	out := []string{}
	for _, w := range ws {
		if p := PlainWarning(w); p != "" {
			out = append(out, p)
		}
	}
	return out
}
