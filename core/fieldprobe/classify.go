package fieldprobe

import (
	"time"

	"daal/bundle-go/fieldreport"
	"daal/core/diagnostics"
)

// The classification table (specs/field-probe-v2.md §"Classification").
// Pure functions of what a probe saw: every path is unit-tested from
// fixtures (classify_test.go), and the loopback tests drive the real
// probe into the paths a loopback can produce.

const (
	carriedBytes = 32 * 1024
	cappedBelow  = 16 * 1024
	// injectedRatio / injectedMinRTT: a reset that arrives sooner after
	// the hello than 0.6 × the connect round trip cannot have come from
	// the server; only measured when the round trip is long enough
	// (≥ 40 ms) for the ratio to mean anything.
	injectedRatio  = 0.6
	injectedMinRTT = 40 * time.Millisecond
)

// classifyTCP turns one TCP probe into (result, phase).
//
// control: whether ANOTHER probe of the run that can stand as this
// one's control carried ≥ 32 KB (fieldprobe's reclassify pass: any
// other Stage B probe for B1–B9; another of C4–C6, to the same address,
// for those). nil while the run is going, or when nothing can stand as
// a control: a stall under 16 KB is then reported as itself (timeout /
// reset), never as a cap — a throttled mobile link, a slow origin or a
// dead address give the same shape, and only a probe on the same
// network that carried tells a cap from those.
func classifyTCP(o tcpObs, control *bool) (result, phase string) {
	capped := control != nil && *control
	switch o.ConnectKind {
	case "":
	case "refused":
		return "refused", "reach"
	case "timeout":
		return "timeout", "reach"
	case "unreachable":
		return "unreachable", "reach"
	default:
		// local_error, local_blocked, other: the device did not let the
		// socket out. Not a finding about the network.
		return "local_error", "reach"
	}
	if !o.HandshakeOK {
		switch {
		case o.FirstEvent == "rst":
			if injectedLikely(o) {
				return "reset_injected_likely", "handshake"
			}
			return "reset", "handshake"
		case o.TLSAlert:
			return "tls_alert", "handshake"
		case o.FirstEvent == "fin":
			return "closed", "handshake"
		case o.FirstEvent == "timeout" || o.FirstEvent == "":
			switch {
			case o.AckKnown && !o.HelloAcked:
				return "silent_drop_forward", "handshake"
			case o.AckKnown && o.HelloAcked && o.Rx == 0:
				return "silent_no_reply", "handshake"
			}
			return "timeout", "handshake"
		case o.FirstEvent == "bytes":
			// Part of the server's flight came, then the handshake did
			// not finish. A stall or a reset under 16 KB here is the
			// grey cap biting on the certificate flight — when a
			// control on this network carried.
			switch o.HandshakeEnd {
			case "timeout", "rst":
				if o.Rx < cappedBelow && capped {
					return "flow_capped_suspected", "handshake"
				}
				if o.HandshakeEnd == "rst" {
					return "reset", "handshake"
				}
				return "timeout", "handshake"
			case "fin":
				return "closed", "handshake"
			}
			// Bytes that were not TLS, or a TLS error on our side.
			return "closed", "handshake"
		}
		return "timeout", "handshake"
	}
	if o.CertChecked && !o.CertValid {
		// Somebody answered for the name with a chain that is not the
		// name's: not the host the list names. Nothing was sent to it.
		return "cert_invalid", "handshake"
	}
	if o.Rx >= carriedBytes {
		return "ok_carried", "carry"
	}
	if o.CarryExpected && (o.EndKind == "timeout" || o.EndKind == "rst") && o.Rx < cappedBelow {
		if capped {
			return "flow_capped_suspected", "carry"
		}
		if o.EndKind == "rst" {
			return "reset", "carry"
		}
		return "timeout", "carry"
	}
	if o.EndKind == "rst" && o.HTTPStatus == 0 {
		return "reset", "carry"
	}
	return "ok", "carry"
}

func injectedLikely(o tcpObs) bool {
	return o.ConnectRTT >= injectedMinRTT && o.FirstAfter > 0 &&
		float64(o.FirstAfter) < injectedRatio*float64(o.ConnectRTT)
}

// tcpSignals buckets what the report may say about one TCP probe.
func tcpSignals(o tcpObs) fieldreport.Signals {
	var s fieldreport.Signals
	if o.ConnectKind != "" {
		return s
	}
	if o.HelloWritten {
		s.HelloFP = o.FP
	}
	s.ConnectRTTBucketMs = fieldreport.RTTBucket(o.ConnectRTT.Milliseconds())
	if o.HelloWritten && o.FirstEvent != "" && o.ConnectRTT > 0 {
		r := int(10 * float64(o.FirstAfter) / float64(o.ConnectRTT))
		if r > 100 {
			r = 100
		}
		if r < 0 {
			r = 0
		}
		s.FirstEventRatioTenths = &r
	}
	if o.AckKnown {
		v := o.HelloAcked
		s.HelloAcked = &v
	}
	s.RxBytesBucket = fieldreport.RxBucket(o.Rx)
	s.HandshakeEnd = o.HandshakeEnd
	if o.CertChecked {
		v := o.CertValid
		s.CertValid = &v
	}
	if o.HandshakeOK && (!o.CertChecked || o.CertValid) {
		s.HTTPStatusClass = fieldreport.HTTPClass(o.HTTPStatus)
	}
	return s
}

// RelayOutcome is one proof of a Test-relay route through the engine's
// side instance (engine.SideProber.SideProbe).
type RelayOutcome struct {
	// Unsupported: the route cannot be side-probed, or the driver has
	// no side prober: nothing was sent.
	Unsupported bool
	Cancelled   bool
	OK          bool
	Obs         diagnostics.Observation
}

// classifyRelay turns a side-probe outcome into (result, phase). The
// phase is the engine's own (diagnostics.Phase); the result follows the
// engine's taxonomy (diagnostics.ClassifyObservation) where the v2
// table has a word for it.
func classifyRelay(r RelayOutcome) (string, string) {
	switch {
	case r.Unsupported, r.Cancelled:
		return "skipped", "none"
	case r.OK:
		return "ok", "carry"
	}
	phase := string(r.Obs.Phase)
	if phase == "" {
		phase = "handshake"
	}
	switch diagnostics.ClassifyObservation(r.Obs) {
	case diagnostics.AuthFailed:
		return "auth_failed", phase
	case diagnostics.RelayNoEgress:
		// The relay's own handshake completed: for this test, reaching
		// it is the question, and it was reached.
		return "ok", "handshake"
	case diagnostics.TLSHandshakeFailed:
		if r.Obs.Closed {
			return "closed", phase
		}
		return "timeout", phase
	case diagnostics.UDPNoReply:
		return "timeout", phase
	}
	switch {
	case r.Obs.Refused:
		return "refused", phase
	case r.Obs.Reset:
		return "reset", phase
	case r.Obs.Closed:
		return "closed", phase
	}
	return "timeout", phase
}

// failureCategory maps a result to the v1 failure tally.
func failureCategory(result, phase string, udp bool) string {
	switch result {
	case "bogon", "answer_altered":
		return "dns_poisoned"
	case "dns_timeout", "servfail", "type_dropped":
		return "dns_timeout"
	case "reset_injected_likely":
		return "tls_sni_or_cert_block_suspected"
	case "reset", "refused", "closed":
		if phase == "handshake" && result == "reset" {
			return "tls_sni_or_cert_block_suspected"
		}
		return "tcp_reset"
	case "timeout":
		if udp {
			return "quic_unavailable"
		}
		if phase == "reach" {
			return "tcp_connect_timeout"
		}
		return "tls_handshake_failed"
	case "silent_drop_forward", "silent_no_reply", "tls_alert":
		return "tls_handshake_failed"
	case "flow_capped_suspected":
		return "flow_capped_suspected"
	case "auth_failed":
		return "auth_failed"
	case "unreachable":
		return "network_offline"
	case "dns_wrong_public":
		return "dns_poisoned"
	case "cert_invalid":
		return "tls_sni_or_cert_block_suspected"
	}
	// local_error is the device, not the network: not tallied.
	return ""
}
