//go:build cshared

// libdaalcore is the c-shared entrypoint that re-exports core/abi's
// engine_* C ABI symbols for the Tauri 2 desktop port (Phase 1.5B) and
// any future c-shared host (e.g., iOS NE extension).
//
// Build:
//
//	go build -buildmode=c-shared -tags cshared \
//	  -o libdaalcore.so ./cmd/libdaalcore
//
// Output naming convention: libdaalcore.so / libdaalcore.dylib /
// libdaalcore.dll alongside the generated libdaalcore.h.
package main

// The blank import pulls in every //export'd symbol in core/abi's
// cshared-tagged files. cgo gathers them into the shared library's
// export table.
import _ "daal/core/abi"

func main() {}
