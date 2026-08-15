//go:build singbox && !(with_naive_outbound && with_purego)

package engine

// loadCronet is a no-op when the engine is built without the naive/Cronet
// outbound (the default). See cronet_loader_naive.go for the real loader.
func loadCronet() {}
