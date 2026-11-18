package main

// Op is a scripted publisher-side operation with its assertions: it
// changes something from the OUTSIDER's seat using real verbs
// (rc.Pub.Deploy / the typed helpers in publisher.go), then proves the
// effect from the INSIDER's seat with rc.Session, recording every claim
// through rc.R.Add with phase "op:<name>".
//
// One op per file (ops_<name>.go), registered in its own init(): three
// people can add three ops without touching the same line.
type Op func(rc *RunCtx)

var Ops = map[string]Op{}
