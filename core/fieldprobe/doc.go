// Package fieldprobe is the network test (field probe v2): a short,
// person-started, bounded series of probes run on the device with every
// VPN off, whose result the person may seal to their publisher and share.
//
// Spec: specs/field-probe-v2.md. Report schema: bundle/go/fieldreport
// (test-rigs/field-probe/schema/probe-report-v2.json). Sealing:
// specs/sealed-report-v1.md.
//
// The package does the probing, the classification and the report. It
// does not decide WHETHER a run may happen (Daal connected, another VPN
// up, the allowance used): core/abi/fieldprobe.go does, and supplies the
// sockets (protect()ed, through the engine's registered callback), the
// Test relay (through the engine's side instance) and the storage.
//
// What it never does: retry, sweep ports, send a bare SYN, ICMP, or a
// TTL-limited packet; resolve or connect to a name that is not in the
// target list; connect to a domestic name or address; put an address,
// a name, a resolver, an SSID or a carrier id into a report or a log.
package fieldprobe
