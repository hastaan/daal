//go:build singbox && !(with_naive_outbound && with_purego)

package engine

// loadCronet is a no-op when the engine is built without the naive/Cronet
// outbound (the default). See cronet_loader_naive.go for the real loader.
//
// It still records an outcome, and the outcome is `false`: an engine
// built without `with_naive_outbound` cannot dial a naive route at
// all, and sing-box's error for that ("naive outbound is not included
// in this build") arrives at connect time, far too late for the UI to
// have told the user. Recording it here is what lets the route list
// say so up front.
func loadCronet() { markCronet(false) }
