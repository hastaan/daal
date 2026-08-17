package rotation

import "strings"

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
	// BindAddress mirrors mgmt.CapBindAddress: the relay can configure
	// an address on its own interface. L3 cannot work without it — a
	// floating IP is routed to the server by the provider but never
	// answered by the guest OS until it is bound.
	BindAddress bool `json:"bind_address"`
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
	return ActionForProvider(level, caps, "")
}

// ActionForProvider is ActionFor plus the one fact L3 turns on: which
// cloud adapter is behind this relay.
//
// WHY L3 NEEDS IT. Since Step 9 the Hetzner adapter reserves an address,
// attaches it, reads it back, and moves rec.PublicIP plus every
// candidate's public_ip:* tag onto it. The Vultr and Stark adapters still
// do what Hetzner did before Step 9 — set FloatingIPID and stop — so on
// those providers a "successful" L3 re-signs a pack aimed at the burned
// address. That is a real difference between two relays and the answer
// has to differ with it.
//
// L3 ALSO NEEDS THE BOX, which is a correction to what this comment used
// to say. It read: "L3 touches the cloud account, not the box, so its
// availability is a property of code in THIS repository". Real hardware
// falsified that on 2026-08-17. A floating IP is ROUTED to the server by
// the provider and never ANSWERED by the guest OS until the address is
// configured on its interface, so the swap now includes a signed call to
// the relay (mgmt.CapBindAddress) — and a relay whose pinned mgmt binary
// predates that endpoint cannot complete an L3 at all. Its availability
// therefore depends on both the adapter and the box's vintage, and the
// answer is only "ready" when both are known good.
//
// An empty or unrecognised providerName yields AvailabilityUnknown,
// which is the same rule the rest of this file follows: not knowing is
// its own state, never rounded up to "ready".
func ActionForProvider(level Level, caps RelayCapabilities, providerName string) Action {
	if level == L3 {
		return floatingIPSwapAction(providerName, caps)
	}
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

// floatingIPSwapAction answers "can this publisher actually swap this
// relay's address?" — per provider adapter, because the answer differs.
//
// Read the note fields as the operator will: each one says what will
// happen if they press the button, not what the roadmap intends.
func floatingIPSwapAction(providerName string, caps RelayCapabilities) Action {
	a := Action{
		Kind:    ActionFloatingIPSwap,
		CLIVerb: "floating-ip",
		Scope:   "server",
		InPlace: true,
		// The address is pinned in every pack's public_ip:* tags and in
		// every client outbound. Moving it strands every already-
		// distributed pack until each recipient gets the new one —
		// which, without the freshness path, means a courier.
		InvalidatesEveryPack: true,
	}
	switch strings.ToLower(strings.TrimSpace(providerName)) {
	case "hetzner":
		// The adapter can do its half. Whether the RELAY can do its half
		// is a separate question with its own three states, and rounding
		// "not asked" up to "ready" is how an operator presses a button
		// that refuses.
		switch {
		case !caps.Known:
			a.Availability = AvailabilityUnknown
			a.Note = "the cloud adapter can swap this relay's address, but the relay itself has not been probed: a floating IP is " +
				"routed to the server by the provider and only ANSWERED once the relay configures it on its interface, and a relay " +
				"whose mgmt binary predates that endpoint will refuse the swap. Probe it (mgmt.CapabilitiesWithFW) before offering this as a one-tap action"
			return a
		case !caps.BindAddress:
			a.Availability = AvailabilityUnsupported
			a.Note = "this relay's software cannot configure an address on its own interface, so an address swapped onto it would " +
				"route to the server and never be answered; the swap refuses before it reserves anything. Re-release daal-relay-mgmt " +
				"and reprovision, or use reprovision now — a rebuilt server gets a new address without needing this endpoint"
			return a
		}
		a.Availability = AvailabilityReady
		a.Note = "reserves an address if you do not supply one, attaches it, confirms the attachment with the provider, tells the relay to " +
			"bind it to its interface, proves the relay answers there, and moves the record's public IP and every candidate public_ip:* tag onto it; " +
			"the relay answers on BOTH addresses until the previous one is unbound and released after the new pack is signed"
		return a
	case "vultr", "stark":
		// Known-unsupported, and it must not read as merely unproven.
		// These adapters set FloatingIPID and return success while
		// rec.PublicIP and the candidate tags still name the burned
		// address, so the rotation would report success and change
		// nothing a censor can see. CheckAddressMoved stops it on the
		// live path (`daal-deploy assign-fip` runs it after the
		// adapter returns), which turns a silent non-rotation into a
		// visible failure — but a rung that always fails is not a
		// rung, so say so before it is pressed.
		a.Availability = AvailabilityUnsupported
		a.Note = "this provider adapter attaches a reserved IP without moving the record onto it, so the swap would leave every pack " +
			"pointing at the address you are rotating away from; the rotation will refuse rather than re-sign a stale pack. " +
			"Use reprovision (a new server gets a new address) until the adapter is updated"
		return a
	default:
		a.Availability = AvailabilityUnknown
		a.Note = unknownProviderNote
		return a
	}
}

const unknownProviderNote = "the record does not say which cloud provider this relay is on, and whether an address swap " +
	"moves the record's public IP depends on the adapter — check the record's provider field before offering this as a one-tap action"

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
