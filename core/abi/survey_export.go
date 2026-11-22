//go:build cshared

package abi

import "C"

import "unsafe"

// engine_survey_routes is the "Check all routes" action and its report
// (survey.go). start 1: check, now, the routes of the file beside the
// tunnel — or with nothing running — in side instances, two at a time;
// it returns at once. start 0: only the report. Either way it writes
// the `survey` block of the diagnostics blob plus two keys:
//
//	{"state":"idle|waiting|checking|done|stopped","trigger":"auto|user|",
//	 "checking":["r2"],"total":3,"done":1,"seq":7,"stop_reason":"",
//	 "results":[{"route_id":"r2","family":"hysteria2",
//	             "result":"carried|not_carrying|start_failed|skipped|when_used|cancelled",
//	             "reason":"fresh|recent|metered|budget|busy|<refusal code>",
//	             "category":"<failure category>","setup_ms":420}],
//	 "started":true,"refused":"|running|busy|unsupported"}
//
// A route whose family cannot be proved beside another (naive, tor,
// wireguard, …) is "when_used". Each result lands where a connect's
// does (this network's memory; a success also in the route store), so
// the route list's scores follow. No address, host or key is ever in it.
// Returns the number of bytes written, or -1 if the engine is not
// initialised.
//
//export engine_survey_routes
func engine_survey_routes(start C.int, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SurveyRoutes(start != 0)
	if err != nil {
		return exportFail("engine_survey_routes", err)
	}
	return copyOut(body, out, outLen)
}
