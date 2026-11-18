package main

import (
	"fmt"
	"strings"
	"time"
)

// A scenario's "prove" list is written against a relay that serves the
// default families: "relay-tls-answers" dials 443/tcp and expects the
// REALITY inbound's cover handshake. A relay provisioned WITHOUT a family
// has nothing on that family's port — no listener and no firewall hole
// (FINDINGS FAM-4, fixed) — so a TCP probe aimed there cannot say
// anything about the censor: it dies at the relay whatever the censor
// does.
//
// Such a probe is not skipped. It is run and its expectation is inverted:
// the relay must NOT accept the connection. That keeps the evidence, and
// turns "a port this relay does not serve answered a stranger" into a red
// check in the one phase that dials the relay with no Daal in the way.
//
// UDP probes are left alone: "delivered" is observed on the wire past the
// censor, not as an answer from the relay, so it is as true of a closed
// port as of an open one.

// relayServesTCP reports whether any family the relay was provisioned
// with listens on port/tcp.
func relayServesTCP(serve []string, fams map[string]Family, port int) bool {
	for _, name := range serve {
		f, ok := fams[name]
		if ok && f.Endpoint.Proto == "tcp" && f.Endpoint.Port == port {
			return true
		}
	}
	return false
}

// tcpProbeRefused reports whether a raw probe's result means "no TCP
// connection was established" — the only outcomes a port the relay does
// not serve may produce.
func tcpProbeRefused(result string) bool {
	switch result {
	case "connect_timeout", "connect_reset", "unreachable", "none":
		return true
	}
	return false
}

// proveUnservedRelayPort handles a prove entry aimed at a relay TCP port
// no served family listens on. It returns false when the entry is an
// ordinary one and the caller should run it as declared.
func (rc *RunCtx) proveUnservedRelayPort(pr Proof, vars map[string]string) bool {
	if pr.To != "relay" || pr.Probe == "udp" || relayServesTCP(rc.Serve, rc.Fams, pr.Port) {
		return false
	}
	t0 := time.Now()
	obs := RawProbeRun(rc.Ctx, rc.P, RawProbe{Kind: pr.Probe, Addr: rc.proofAddr(pr.To), Port: pr.Port,
		SNI: substVars(pr.SNI, vars), Split: pr.Split, Shape: pr.Shape})
	refused := tcpProbeRefused(obs.Result)
	detail := fmt.Sprintf("this relay serves %s and nothing on %d/tcp, so the probe proves nothing about the censor; asserted instead: the relay does not accept a connection there (saw %q)",
		strings.Join(rc.Serve, ","), pr.Port, obs.Result)
	if !refused {
		detail = fmt.Sprintf("the relay serves %s — no family on %d/tcp — and yet a raw %s probe there saw %q: something is listening and reachable on a port this relay was not provisioned to serve",
			strings.Join(rc.Serve, ","), pr.Port, pr.Probe, obs.Result)
	}
	rc.R.Add("", "censor", "prove."+pr.Name, Blocked, got(refused, Blocked, Pass), detail,
		map[string]any{"probe": pr.Probe, "to": pr.To, "addr": obs.Addr, "port": pr.Port, "sni": obs.SNI,
			"declared": pr.Expect, "observed": obs.Result, "error": obs.Error, "probe_ms": obs.Ms,
			"relay_serves": rc.Serve, "inverted": "no served family listens on this TCP port"}, t0)
	return true
}
