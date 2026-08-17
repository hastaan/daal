package rotation

// WHY THIS FILE EXISTS
//
// Until Step 7 the recommender named rungs nothing could execute. It
// would answer "L1: rotate credentials, ~90s" and the only thing the
// publisher could actually do was `reprovision --regen-credentials`:
// destroy the server, build a new one, ~3 minutes, new IP, new mgmt TLS
// pin, and every recipient needing a fresh pack — to change a password.
// The same for L2. The advice was honest about the ladder and dishonest
// about the machine.
//
// An Action closes that gap: every recommendation now carries the
// concrete operation behind it — which verb runs it, what it touches,
// whether the server survives, and whether the relay in front of you
// can actually do it. A rung with no executable action says so instead
// of implying one.
//
// It is also the recommender's half of the capability problem. The
// relay's in-box mgmt binary is a hash-pinned artifact that only a
// human re-release updates, so at any moment the fleet holds both
// vintages. The recommender is pure and offline (Position B: no
// network), so it cannot probe; the caller probes with
// mgmt.CapabilitiesWithFW and passes the answer in. Three states, not
// two — "not known yet" is distinct from "known unsupported", and
// pretending otherwise is exactly the class of lie the honesty pass
// removed elsewhere.

// RelayCapabilities is what the publisher has learned about a specific
// relay's in-box mgmt binary.
//
// Known distinguishes "we probed" from "we have not". A zero value
// means unprobed, which is the safe default for a struct that is often
// left unset: it produces AvailabilityUnknown, never a confident claim.
type RelayCapabilities struct {
	// Known is true only if the publisher actually probed this relay
	// (mgmt.CapabilitiesWithFW). False ⇒ the two booleans below carry
	// no information.
	Known bool `json:"known"`
	// RotateCredentialsInPlace mirrors mgmt.CapRotateCredentialsScoped.
	RotateCredentialsInPlace bool `json:"rotate_credentials_in_place"`
	// RotateTLSInPlace mirrors mgmt.CapRotateTLSScoped.
	RotateTLSInPlace bool `json:"rotate_tls_in_place"`
}

// ActionKind is the closed set of operations the publisher can actually
// perform. Each value is a real, callable thing today.
type ActionKind string

const (
	// ActionRotateCredentials: `daal-deploy rotate-credentials`, in
	// place, one recipient.
	ActionRotateCredentials ActionKind = "rotate-credentials"
	// ActionRotateTLS: `daal-deploy rotate-tls`, in place, relay-wide.
	ActionRotateTLS ActionKind = "rotate-tls"
	// ActionFloatingIPSwap: `daal-deploy floating-ip --op assign`.
	ActionFloatingIPSwap ActionKind = "floating-ip-swap"
	// ActionReprovision: `daal-deploy reprovision`. Destroys the box.
	ActionReprovision ActionKind = "reprovision"
)

// Availability answers "can the relay in front of me do this?".
type Availability string

const (
	// AvailabilityReady: probed, and the relay advertises it.
	AvailabilityReady Availability = "ready"
	// AvailabilityUnknown: not probed. The UI must probe (or say
	// "unverified") rather than render a confident button.
	AvailabilityUnknown Availability = "unknown"
	// AvailabilityUnsupported: probed, and the relay cannot. The
	// Action returned in this state is the FALLBACK, not the wish.
	AvailabilityUnsupported Availability = "unsupported"
)

// Action is the executable operation behind a ladder rung.
type Action struct {
	Kind    ActionKind `json:"kind"`
	CLIVerb string     `json:"cli_verb"`
	// Scope: "recipient" | "relay" | "server". How much of the world
	// this touches if it goes wrong.
	Scope string `json:"scope"`
	// InPlace: the server survives and keeps its IP.
	InPlace bool `json:"in_place"`
	// NeedsRecipientName: the caller must supply --name. True only for
	// the per-recipient revocation.
	NeedsRecipientName bool `json:"needs_recipient_name"`
	// DestroysServer: the box is deleted and rebuilt. New IP, new mgmt
	// TLS pin, minutes not seconds.
	DestroysServer bool `json:"destroys_server"`
	// InvalidatesEveryPack: after this runs, EVERY already-distributed
	// pack stops working until its recipient gets a new one. Under
	// blackout that redistribution is the thing that does not work, so
	// this flag is the difference between a targeted fix and an outage.
	InvalidatesEveryPack bool         `json:"invalidates_every_pack"`
	Availability         Availability `json:"availability"`
	Note                 string       `json:"note,omitempty"`
}

// unsupportedNote is the operator-facing sentence for a relay whose
// pinned mgmt artifact predates the in-place verbs. It matches the
// wording mgmt uses so the CLI, the wizard and the recommender do not
// each invent their own.
const unsupportedNote = "this relay's software is too old to rotate in place; " +
	"reprovision the relay, or re-release daal-relay-mgmt and reprovision"

const unknownNote = "not probed yet — ask the relay (mgmt.CapabilitiesWithFW) before offering this as a one-tap action"

// ActionFor maps a ladder rung onto the operation that performs it,
// given what is known about the relay.
//
// The two in-place rungs degrade rather than lie: a relay known not to
// support them comes back with the reprovision fallback, marked
// unsupported and carrying the remediation. A relay not yet probed
// comes back with the in-place action marked unknown — the right shape,
// with an explicit "verify first".
func ActionFor(level Level, caps RelayCapabilities) Action {
	switch level {
	case L1:
		a := Action{
			Kind:               ActionRotateCredentials,
			CLIVerb:            "rotate-credentials",
			Scope:              "recipient",
			InPlace:            true,
			NeedsRecipientName: true,
			// A targeted revocation. Nobody else's pack is touched —
			// that is precisely what the Step-7 split bought.
			InvalidatesEveryPack: false,
		}
		return withAvailability(a, caps.Known, caps.RotateCredentialsInPlace, fallbackReprovision(
			"relay cannot rotate credentials in place; reprovision --regen-credentials rebuilds the box instead"))
	case L2:
		a := Action{
			Kind:    ActionRotateTLS,
			CLIVerb: "rotate-tls",
			Scope:   "relay",
			InPlace: true,
			// The cover host is pinned in every pack. Moving it on the
			// box strands every pack until each is re-minted.
			InvalidatesEveryPack: true,
		}
		return withAvailability(a, caps.Known, caps.RotateTLSInPlace, fallbackReprovision(
			"relay cannot rotate TLS in place; reprovision --new-sni rebuilds the box instead"))
	case L3:
		return Action{
			Kind:                 ActionFloatingIPSwap,
			CLIVerb:              "floating-ip",
			Scope:                "server",
			InPlace:              true,
			InvalidatesEveryPack: true,
			// NOT "ready", however cheap the rung looks. The floating-IP
			// swap does not yet move the address anyone dials:
			// hetzner.AssignFloatingIP sets rec.FloatingIPID and nothing
			// else, so rec.PublicIP and the candidates' public_ip:* tags
			// still name the burned address and a pack re-signed after an
			// L3 points straight back at it. There is also no
			// floating-IP CREATION anywhere in the repo, so the operator
			// must have reserved one by hand and know its numeric ID.
			// Marking this "ready" would tell a reader — the wizard, or a
			// human running rotate-recommend — that the cheapest recovery
			// rung is a working one-tap action, which is the precise lie
			// this file's header says an Action exists to end. Step 9 is
			// what makes it true; until then the honest state is "not
			// something this publisher can confirm it can do".
			Availability: AvailabilityUnknown,
			Note: "not usable yet: the floating-IP swap does not update the record's public IP or its candidate tags, " +
				"so a pack re-signed after it still points at the old address; it also requires a floating IP reserved by hand",
		}
	case L4, L5, L6:
		return Action{
			Kind:                 ActionReprovision,
			CLIVerb:              "reprovision",
			Scope:                "server",
			DestroysServer:       true,
			InvalidatesEveryPack: true,
			Availability:         AvailabilityReady,
		}
	default:
		return Action{Availability: AvailabilityUnknown, Note: "no executable action for this level"}
	}
}

// withAvailability stamps the three-state answer onto an in-place
// action, swapping in the fallback when the relay is known not to
// support it.
func withAvailability(a Action, known, supported bool, fallback Action) Action {
	switch {
	case !known:
		a.Availability = AvailabilityUnknown
		a.Note = unknownNote
		return a
	case supported:
		a.Availability = AvailabilityReady
		return a
	default:
		fallback.Availability = AvailabilityUnsupported
		return fallback
	}
}

// fallbackReprovision builds the destroy-and-rebuild action an old
// relay leaves as the only route to the same outcome.
func fallbackReprovision(why string) Action {
	return Action{
		Kind:                 ActionReprovision,
		CLIVerb:              "reprovision",
		Scope:                "server",
		DestroysServer:       true,
		InvalidatesEveryPack: true,
		Note:                 why + " — " + unsupportedNote,
	}
}
