package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// The wire tap: what actually crossed the censor, per family endpoint.
//
// A fetch that succeeds and arrives from the relay's egress address proves
// that SOME tunnel carried it. It does not prove WHICH: a route the engine
// lists as "tuic" whose profile is a vless outbound would pass every
// end-to-end check and never put a QUIC packet on the wire — the family
// would still have "never carried a byte". The censor is the one place
// every client↔relay packet passes, so the tap lives there:
//
//	table inet wb_wire, hook forward, priority -200 (BEFORE the scenario's
//	filter at 0: a packet the censor then drops is still an attempt, and
//	"blocked" must be told apart from "never tried").
//
// Three named counters per served family endpoint — <family>.new (flows
// the CLIENT opened to the family's port/proto), <family>.in (every packet
// of them) and <family>.out (the replies) — and other.* for anything else
// between the two addresses. Nothing here filters; every rule is a counter.
//
// "Somewhere else" is judged on .new only: a connection the client opened
// during this session. Late packets of the previous session (a FIN's ACK,
// a QUIC close retransmit, the kernel's RST for a socket that is gone) are
// not new flows and say nothing about this one. That needs connection
// tracking in the censor namespace, which a real middlebox has anyway.
const wireTable = "wb_wire"

// WireSample is the traffic seen since the previous sample.
type WireSample map[string]WireCount

type WireCount struct {
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

// InstallWireTap (re)creates the tap for the families the relay serves.
func InstallWireTap(ctx context.Context, fams []Family) error {
	// Every address the relay can be reached on: its primary one and any
	// floating IP the cloud may route to it (an L3 move must not look like
	// "the session went somewhere else"; see fakecloud_fip.go).
	relay := RelayPublicAddrSet()
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", wireTable, wireTable, wireTable)
	names := []string{"other"}
	for _, f := range fams {
		names = append(names, f.Name)
	}
	for _, n := range names {
		fmt.Fprintf(&b, "  counter %s { }\n  counter %s { }\n  counter %s { }\n", n+".new", n+".in", n+".out")
	}
	b.WriteString("  chain forward { type filter hook forward priority -200; policy accept;\n")
	for _, f := range fams {
		fmt.Fprintf(&b, "    ip saddr %s ip daddr %s %s dport %d ct state new counter name %s\n", ClientIP, relay, f.Endpoint.Proto, f.Endpoint.Port, f.Name+".new")
		fmt.Fprintf(&b, "    ip saddr %s ip daddr %s %s dport %d counter name %s return\n", ClientIP, relay, f.Endpoint.Proto, f.Endpoint.Port, f.Name+".in")
		fmt.Fprintf(&b, "    ip saddr %s ip daddr %s %s sport %d counter name %s return\n", relay, ClientIP, f.Endpoint.Proto, f.Endpoint.Port, f.Name+".out")
	}
	fmt.Fprintf(&b, "    ip saddr %s ip daddr %s ct state new counter name other.new\n", ClientIP, relay)
	fmt.Fprintf(&b, "    ip saddr %s ip daddr %s counter name other.in return\n", ClientIP, relay)
	fmt.Fprintf(&b, "    ip saddr %s ip daddr %s counter name other.out return\n", relay, ClientIP)
	b.WriteString("  }\n}\n")
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", NSCensor, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wire tap: nft: %v: %s", err, out)
	}
	return nil
}

// WireReset returns what the tap counted since the last reset and zeroes
// it (one atomic nft operation). Sessions run one at a time, so the window
// between two resets is exactly one session's traffic.
func WireReset(ctx context.Context) (WireSample, error) {
	out, err := exec.CommandContext(ctx, "ip", "netns", "exec", NSCensor, "nft", "-j", "reset", "counters", "table", "inet", wireTable).Output()
	if err != nil {
		return nil, fmt.Errorf("wire tap: reset: %w", err)
	}
	return parseWire(out)
}

func parseWire(out []byte) (WireSample, error) {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets int64  `json:"packets"`
				Bytes   int64  `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("wire tap: %w", err)
	}
	s := WireSample{}
	for _, o := range doc.Nftables {
		if o.Counter != nil {
			s[o.Counter.Name] = WireCount{o.Counter.Packets, o.Counter.Bytes}
		}
	}
	if len(s) == 0 {
		return nil, fmt.Errorf("wire tap: no counters in the censor namespace (tap not installed?)")
	}
	return s, nil
}

// Verdict judges a sample against "this session was family f and it
// carried at least minDown bytes of payload towards the client".
//
//	pass     f's endpoint carried it, both directions, at least minDown
//	         bytes down — and the client opened no flow to anything else
//	         on the relay
//	fail     the client opened a flow somewhere the family does not live
//	blocked  the client tried f's endpoint and too little came back
//	silent   not one packet towards f's endpoint: nothing was attempted
func (s WireSample) Verdict(family string, minDown int64) (verdict, detail string) {
	in, out := s[family+".in"], s[family+".out"]
	var strays []string
	for name, c := range s {
		if c.Packets > 0 && strings.HasSuffix(name, ".new") && name != family+".new" {
			strays = append(strays, fmt.Sprintf("%d new flow(s) to %s", c.Packets, strings.TrimSuffix(name, ".new")))
		}
	}
	sort.Strings(strays)
	switch {
	case len(strays) > 0:
		return Fail, fmt.Sprintf("a %s session opened connections somewhere other than %s's endpoint: %s (own endpoint: in=%dpkt out=%dpkt/%dB)",
			family, family, strings.Join(strays, ", "), in.Packets, out.Packets, out.Bytes)
	case in.Packets == 0:
		return "silent", fmt.Sprintf("no packet from the client to %s's endpoint", family)
	case out.Packets == 0 || out.Bytes < minDown:
		return Blocked, fmt.Sprintf("client sent %d packets to %s's endpoint; %d packets / %d bytes came back (payload alone is %d)", in.Packets, family, out.Packets, out.Bytes, minDown)
	}
	return Pass, ""
}

// Evidence is the non-zero part of a sample, for a check's evidence field.
func (s WireSample) Evidence() map[string]any {
	ev := map[string]any{}
	for name, c := range s {
		if c.Packets > 0 {
			ev[name] = map[string]int64{"packets": c.Packets, "bytes": c.Bytes}
		}
	}
	return ev
}
