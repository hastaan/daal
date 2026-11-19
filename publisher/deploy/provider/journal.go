package provider

import (
	"context"
	"errors"
	"net"
)

// ProvisionJournal is the provision run's own record of what it is about
// to create and what it did create, written AS it happens so a run that
// is killed between any two instructions still leaves evidence behind.
//
// The app on a phone can be killed at any moment, and its child process
// with it: no rollback runs, no defer runs, and the OperatorRecord that
// is normally written on success never is. Before this journal the only
// trace of a paid server created by such a run was its name on the
// provider's side. The journal is the first-hand account; the ownership
// labels and derived names (account audit) stay the backstop when a
// line is missing.
//
// Order is the contract: Intent BEFORE each create call, Created
// immediately after it returns and before any other cloud call. An
// adapter must abort (before creating anything) when Begin or Intent
// fails — a create the journal does not know about is exactly what this
// exists to prevent. Created/Deleted/Phase report their own write
// failures out of band (the resource exists either way) and never stop
// the run.
//
// NOTHING SECRET GOES IN HERE: not the API token, not the health token,
// not a private key. Only ids, names, addresses, ports and the public
// publisher key.
type ProvisionJournal interface {
	// Begin records which of the three server-selection paths this run
	// took ("create", "adopt", "rebuild_yours", or "reuse" for the
	// legacy --mgmt-port adopt that creates nothing) plus the values
	// the adapter resolved: the derived relay name, the management port
	// and the cover host.
	Begin(mode, relayName string, mgmtPort int, coverSNI string) error
	// Intent is written immediately before a create (or rebuild) call.
	// id is only set for kind "rebuild".
	Intent(kind, name, id string) error
	// Created is written immediately after a create returns.
	Created(kind, id, name string, publicIP net.IP)
	// Deleted is written after a successful delete.
	Deleted(kind, id string)
	// Phase is informational ("health_wait", "healthy").
	Phase(step string)
}

// Journal entry kinds. KindServer / KindFloatingIP / KindSSHKey /
// KindFirewall from audit.go are shared; rebuild is journal-only.
const JournalKindRebuild = "rebuild"

// Journal begin modes.
const (
	ModeCreate       = "create"
	ModeAdopt        = "adopt"
	ModeRebuildYours = "rebuild_yours"
	// ModeReuse is the pre-existing "--mgmt-port given, server exists"
	// path: it creates and changes nothing and returns a record for the
	// box as it stands.
	ModeReuse = "reuse"
)

type noopJournal struct{}

func (noopJournal) Begin(string, string, int, string) error { return nil }
func (noopJournal) Intent(string, string, string) error     { return nil }
func (noopJournal) Created(string, string, string, net.IP)  {}
func (noopJournal) Deleted(string, string)                  {}
func (noopJournal) Phase(string)                            {}

// J returns the run's journal, or a no-op one when the caller passed
// none (tests, the dry run, an older caller).
func (o ProvisionOpts) J() ProvisionJournal {
	if o.Journal == nil {
		return noopJournal{}
	}
	return o.Journal
}

// Closed set of provision failure codes. The same code goes on the
// `provision_error` progress line and into the journal's `failed` line.
const (
	CodeServerExists      = "server_exists"
	CodeNotOurs           = "not_ours"
	CodeResumeUnsupported = "resume_unsupported"
	CodeHealthTimeout     = "health_timeout"
	CodeCloudInitFailed   = "cloud_init_failed"
	CodeCloudError        = "cloud_error"
	CodeCancelled         = "cancelled"
	CodeJournalBusy       = "journal_busy"
	CodeJournalError      = "journal_error"
	CodeBadInput          = "bad_input"
)

// ProvisionError carries a closed-set code (and, for server_exists, the
// id of the server that is in the way) through the error chain from an
// adapter to the CLI. Adapters wrap; the CLI unwraps with
// ProvisionErrorCode.
type ProvisionError struct {
	Code     string
	ServerID string
	Err      error
}

func (e *ProvisionError) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Err.Error()
}

func (e *ProvisionError) Unwrap() error { return e.Err }

// Coded wraps err with a provision failure code.
func Coded(code string, err error) error {
	if err == nil {
		return nil
	}
	return &ProvisionError{Code: code, Err: err}
}

// ProvisionErrorCode classifies a Provision failure into the closed set.
// An error that carries no code is a cloud error, except a cancelled
// context, which is "cancelled".
func ProvisionErrorCode(err error) (code, serverID string) {
	if err == nil {
		return "", ""
	}
	var pe *ProvisionError
	if errors.As(err, &pe) && pe.Code != "" {
		return pe.Code, pe.ServerID
	}
	if errors.Is(err, context.Canceled) {
		return CodeCancelled, ""
	}
	return CodeCloudError, ""
}
