package main

import (
	"bytes"
	"fmt"
	"sort"
	"time"
)

func init() { Ops["desync"] = opDesync }

// opDesync: the PRODUCTION ClientHello split (core/desync, plan T2),
// against the censor of this world.
//
// The scenario's own proofs (censor_probe.go, `split: true`) show the
// premise with a probe-harness conn: a hello cut in two slips past a box
// that reads only the first packet. This op closes the gap the plan's
// verification report names — it is the engine that cuts. For each
// family whose outbound the split can sit under, and each preset the
// scenario declares (Scenario.Desync; sni-cut alone when it declares
// none), one fresh phone imports r1's pack and connects with the preset
// turned on for its route, exactly as the selection ladder will turn it
// on (wb-client --desync → engine.SetRouteDesync → BuildSingBoxConfig
// puts the route's outbound behind the daal-desync detour). Checks,
// under "<preset>.":
//
//	the session's own   tunnel / wire / … with the scenario's desync
//	                    expectation (a split the box cannot read passes
//	                    where the stock hello is blocked; one it can read
//	                    is blocked like the stock hello)
//	first_segment       at the censor's client-side interface, every TCP
//	                    flow the phone opened to the family's endpoint
//	                    began with a 1-byte data packet (the presets that
//	                    cut at 1): the split happened on the wire, not
//	                    just in a config
//	name_cut            in every such flow whose first packets carry the
//	                    cover host's name, no single data packet holds the
//	                    whole name (sni-cut, chain, tlsrec-sni), and for
//	                    sni-cut not the first two joined either: the cut
//	                    fell inside the name, wherever the hello put it.
//	                    split1 does not claim this: recorded, not judged.
//
// Nothing here changes the pack: the publisher has no say in this op
// (the signed `_desync` offer is a later publisher change).
func opDesync(rc *RunCtx) {
	const phase = "op:desync"
	t0 := time.Now()
	if err := StartFlowTap(rc.Ctx, rc.P); err != nil {
		rc.R.Add("", phase, "flowtap", Pass, Fail, err.Error(), nil, t0)
		return
	}
	presets := make([]string, 0, len(rc.Scn.Desync))
	for p := range rc.Scn.Desync {
		presets = append(presets, p)
	}
	sort.Strings(presets)
	if len(presets) == 0 {
		presets = []string{"sni-cut"}
	}
	for _, f := range rc.activeFamilies() {
		if why, refused := desyncRefused[f.Name]; refused {
			rc.desyncRefusedSessions(f, phase, presets, why)
			continue
		}
		if !desyncFamilies[f.Name] {
			rc.R.Add(f.Name, phase, "sessions", Skipped, Skipped,
				"the split cannot sit under this family's outbound ("+desyncWhyNot(f.Name)+")", nil, time.Now())
			continue
		}
		for _, preset := range presets {
			expect, err := rc.Scn.DesyncExpect(preset, f.Name)
			if err != nil {
				rc.R.Add(f.Name, phase, preset+".expectation", Pass, Fail, err.Error(), nil, time.Now())
				continue
			}
			from := time.Now()
			saved := rc.R.prefix
			rc.R.prefix = preset + "."
			rc.desync = fmt.Sprintf(`{"preset":%q}`, preset)
			outcome := rc.Session(f, rc.Pack, phase, expect)
			rc.desync = ""
			rc.R.prefix = saved
			rc.desyncFirstSegment(f, phase, preset, outcome, from)
		}
	}
}

// desyncFamilies are the families whose route outbound the engine puts
// behind the desync detour (core/engine desync.go desyncTypes and
// desyncApplicable: vless, anytls, …). Not naive (Cronet opens its own
// sockets), not hysteria2 / tuic (UDP: no TCP hello), and not
// shadowsocks (desyncRefused).
var desyncFamilies = map[string]bool{"vless-reality": true, "websocket-tls": true, "anytls": true}

// desyncRefused are the families the detour COULD sit under and the
// engine must refuse to cut, and why. They still get one session per
// preset — the phone asks for the cut exactly as for the others — and
// the checks are that the route works and that nothing was cut.
//
// shadowsocks: a cut breaks it. Its server reads the fixed-length
// request header with one Read and resets the connection when that Read
// is short (sing-shadowsocks shadowaead_2022, ErrBadHeader), and every
// preset's first segment is 1 byte. Until the engine refused it, split1,
// sni-cut and chain turned this family's working route into tcp_reset
// on 8446 in both sni-rst worlds — while there was nothing to hide: the
// stream has no ClientHello, so no SNI filter reads it uncut either.
var desyncRefused = map[string]string{
	"shadowsocks": "its server reads the request header in one Read and resets on a short one; there is no ClientHello to hide",
}

// desyncRefusedSessions: for a family the engine must not cut, each
// preset asked for still connects (the scenario's desync expectation,
// which for these families is the same as without the cut), and the
// censor-side tap shows no flow that began with the 1-byte segment every
// preset would have sent.
func (rc *RunCtx) desyncRefusedSessions(f Family, phase string, presets []string, why string) {
	for _, preset := range presets {
		expect, err := rc.Scn.DesyncExpect(preset, f.Name)
		if err != nil {
			rc.R.Add(f.Name, phase, preset+".expectation", Pass, Fail, err.Error(), nil, time.Now())
			continue
		}
		from := time.Now()
		saved := rc.R.prefix
		rc.R.prefix = preset + "."
		rc.desync = fmt.Sprintf(`{"preset":%q}`, preset)
		outcome := rc.Session(f, rc.Pack, phase, expect)
		rc.desync = ""
		rc.R.prefix = saved
		t0 := time.Now()
		check := preset + ".not_cut"
		if outcome == Skipped || outcome == Refused {
			rc.R.Add(f.Name, phase, check, Skipped, Skipped, "the session did not dial ("+outcome+")", nil, t0)
			continue
		}
		pkts, err := ReadFlowTap(rc.P)
		if err != nil {
			rc.R.Add(f.Name, phase, check, Pass, Fail, "flow tap: "+err.Error(), nil, t0)
			continue
		}
		var flows [][]int
		cut := 0
		for _, fd := range firstData(pkts, f.Endpoint.Port, from, time.Now()) {
			flows = append(flows, fd.Sizes)
			if len(fd.Sizes) > 0 && fd.Sizes[0] == 1 {
				cut++
			}
		}
		ev := map[string]any{"port": f.Endpoint.Port, "flows": len(flows), "first_data_packets": flows, "why": why}
		switch {
		case len(flows) == 0:
			rc.R.Add(f.Name, phase, check, Pass, Fail, "no TCP flow to the family's endpoint opened during the session", ev, t0)
		case cut > 0:
			rc.R.Add(f.Name, phase, check, Pass, Fail,
				fmt.Sprintf("%d of %d flows began with a 1-byte data packet: the engine cut a %s route (%s)", cut, len(flows), f.Name, why), ev, t0)
		default:
			rc.R.Add(f.Name, phase, check, Pass, Pass, "", ev, t0)
		}
	}
}

func desyncWhyNot(family string) string {
	switch family {
	case "naive":
		return "Cronet dials the relay itself; sing-box's detour never reaches it"
	case "hysteria2", "tuic":
		return "a UDP family: there is no TCP ClientHello to cut"
	}
	return "not a family the engine applies it to"
}

// desyncFirstSegment reads the censor-side packet log for the session.
func (rc *RunCtx) desyncFirstSegment(f Family, phase, preset, outcome string, from time.Time) {
	t0 := time.Now()
	check := preset + ".first_segment"
	if outcome == Skipped || outcome == Refused {
		rc.R.Add(f.Name, phase, check, Skipped, Skipped, "the session did not dial ("+outcome+")", nil, t0)
		return
	}
	pkts, err := ReadFlowTap(rc.P)
	if err != nil {
		rc.R.Add(f.Name, phase, check, Pass, Fail, "flow tap: "+err.Error(), nil, t0)
		return
	}
	data := firstData(pkts, f.Endpoint.Port, from, time.Now())
	var flows [][]int
	for _, fd := range data {
		flows = append(flows, fd.Sizes)
	}
	ev := map[string]any{"port": f.Endpoint.Port, "flows": len(flows), "first_data_packets": flows}
	got, note, nev := nameCutVerdict(preset, data, rc.Rec.CoverSNI)
	want := Pass
	if got == Skipped {
		want = Skipped
	}
	rc.R.Add(f.Name, phase, preset+".name_cut", want, got, note, nev, t0)
	if preset == "tlsrec-sni" {
		// Cut at the record boundary, which depends on where the name is
		// (and is no cut at all on a family whose hello has none):
		// recorded, not judged.
		rc.R.Add(f.Name, phase, check, Skipped, Skipped, "record-split preset: the first segment's size depends on the hello", ev, t0)
		return
	}
	if len(flows) == 0 {
		rc.R.Add(f.Name, phase, check, Pass, Fail, "no TCP flow to the family's endpoint opened during the session", ev, t0)
		return
	}
	carried := 0
	for i, sizes := range flows {
		if len(sizes) == 0 {
			continue // a flow that never carried data (the relay refused it, a dial the engine gave up)
		}
		carried++
		if sizes[0] != 1 {
			rc.R.Add(f.Name, phase, check, Pass, Fail,
				fmt.Sprintf("flow %d of %d began with a %d-byte data packet, not the 1-byte first segment %s cuts", i+1, len(flows), sizes[0], preset), ev, t0)
			return
		}
	}
	if carried == 0 {
		rc.R.Add(f.Name, phase, check, Pass, Fail, "no flow to the family's endpoint carried a single data packet", ev, t0)
		return
	}
	rc.R.Add(f.Name, phase, check, Pass, Pass, "", ev, t0)
}

// nameCutVerdict judges where the cover host's name fell in each flow's
// first data packets (the flow tap keeps their bytes). A flow whose
// kept packets, joined, never hold the name (another family's name, no
// name, a hello longer than what was kept) is not judged; with none
// judged the check is Skipped.
func nameCutVerdict(preset string, flows []flowData, name string) (outcome, note string, ev map[string]any) {
	ev = map[string]any{}
	if preset == "split1" {
		return Skipped, "split1 cuts before the record header only; it does not claim to cut the name", ev
	}
	if name == "" {
		return Skipped, "no cover host name to look for", ev
	}
	needle := []byte(name)
	judged := 0
	var where [][]int // per judged flow: the packet indexes the name spans
	for i, fd := range flows {
		var joined []byte
		for _, p := range fd.Payloads {
			joined = append(joined, p...)
		}
		at := bytes.Index(joined, needle)
		if at < 0 {
			// Split across TLS records (tlsrec-sni): a record header sits
			// inside the name. Judged when the records' payloads, joined,
			// hold it — then no packet holds it contiguous, which is the
			// property: a box that parses one record never sees it.
			if !bytes.Contains(deframeTLS(joined), needle) {
				continue
			}
			judged++
			for k, p := range fd.Payloads {
				if bytes.Contains(p, needle) {
					return Fail, fmt.Sprintf("flow %d: data packet %d (%d bytes) holds the whole server_name", i+1, k+1, len(p)), ev
				}
			}
			where = append(where, []int{-1}) // across records
			continue
		}
		judged++
		off, span := 0, []int{}
		for k, p := range fd.Payloads {
			if off < at+len(needle) && off+len(p) > at {
				span = append(span, k)
			}
			if bytes.Contains(p, needle) {
				ev["spans"] = append(where, span)
				return Fail, fmt.Sprintf("flow %d: data packet %d (%d bytes) holds the whole server_name", i+1, k+1, len(p)), ev
			}
			off += len(p)
		}
		where = append(where, span)
		if preset == "sni-cut" && len(fd.Payloads) >= 2 {
			two := append(append([]byte(nil), fd.Payloads[0]...), fd.Payloads[1]...)
			if bytes.Contains(two, needle) {
				ev["spans"] = where
				return Fail, fmt.Sprintf("flow %d: the first two data packets (%d+%d bytes) together hold the whole server_name", i+1, fd.Sizes[0], fd.Sizes[1]), ev
			}
		}
	}
	ev["flows_judged"], ev["spans"] = judged, where
	if judged == 0 {
		return Skipped, "no flow's first data packets carried the cover host's name", ev
	}
	return Pass, "", ev
}

// deframeTLS joins the payloads of the TLS records b opens with (the
// last one possibly incomplete); nil when b is not TLS records.
func deframeTLS(b []byte) []byte {
	var out []byte
	for len(b) >= 5 && b[0] >= 0x14 && b[0] <= 0x17 && b[1] == 3 {
		n := int(b[3])<<8 | int(b[4])
		b = b[5:]
		if n > len(b) {
			n = len(b)
		}
		out = append(out, b[:n]...)
		b = b[n:]
	}
	return out
}
