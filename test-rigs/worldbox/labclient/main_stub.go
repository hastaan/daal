//go:build !(singbox && cgo && linux)

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "wb-client: built without the data plane; build with -tags singbox,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api and cgo on linux")
	os.Exit(2)
}
