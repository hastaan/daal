package desync

import (
	"sync"
	"sync/atomic"
)

// What separated a cut first flight's segments, as one closed word (the
// `ack=` of the log line and of Stats). An on-device run reads it to
// tell "the kernel's ACK and sent-queue guard worked" from "only sleeps
// did", which the wire alone cannot show.
const (
	// AckTCPInfo: the socket was found and TCP_INFO answered: the ACK
	// wait (when the strategy asks for it) and the autocork guard ran.
	AckTCPInfo = "tcpinfo"
	// AckDelay: no socket under the wrappers, or no TCP_INFO on this
	// platform: delays alone separated the segments.
	AckDelay = "delay"
)

// FlightReport is what one cut first flight did. It holds counts and
// closed words only: never an address, a name or a byte of the flight.
type FlightReport struct {
	Segments int    // segments planned
	Ack      string // AckTCPInfo or AckDelay
	// AckTimeouts: gaps whose ACK wait ended without the ACK.
	AckTimeouts int
	// BudgetSpent: the first-flight budget (or the write deadline) ran
	// out and the rest left in one piece.
	BudgetSpent bool
}

// Stats are process-wide counters of cut first flights.
type Stats struct {
	Flights, AckTCPInfo, AckDelay, AckTimeouts, BudgetSpent uint64
}

var stats struct {
	flights, tcpinfo, delay, ackTimeouts, budget atomic.Uint64
}

// ReadStats returns the counters so far.
func ReadStats() Stats {
	return Stats{
		Flights:     stats.flights.Load(),
		AckTCPInfo:  stats.tcpinfo.Load(),
		AckDelay:    stats.delay.Load(),
		AckTimeouts: stats.ackTimeouts.Load(),
		BudgetSpent: stats.budget.Load(),
	}
}

var (
	logMu   sync.Mutex
	logFn   func(string)
	logSeen = map[string]bool{}
)

// SetLogger sets where the package's few log lines go (the engine sets
// its own LogInfo). Each line is a closed word, logged the first time it
// is seen in the process: "desync: first flight ack=delay" says once
// that this platform or this dial chain cuts on sleeps alone.
func SetLogger(f func(string)) {
	logMu.Lock()
	defer logMu.Unlock()
	logFn = f
}

func logOnce(line string) {
	logMu.Lock()
	defer logMu.Unlock()
	if logFn == nil || logSeen[line] {
		return
	}
	logSeen[line] = true
	logFn(line)
}

func record(r FlightReport) {
	stats.flights.Add(1)
	if r.Ack == AckTCPInfo {
		stats.tcpinfo.Add(1)
	} else {
		stats.delay.Add(1)
	}
	stats.ackTimeouts.Add(uint64(r.AckTimeouts))
	logOnce("desync: first flight ack=" + r.Ack)
	if r.AckTimeouts > 0 {
		logOnce("desync: first flight ack wait timed out")
	}
	if r.BudgetSpent {
		stats.budget.Add(1)
		logOnce("desync: first flight budget spent, rest sent whole")
	}
}
