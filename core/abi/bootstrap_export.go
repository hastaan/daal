//go:build cshared

package abi

import "C"

import "unsafe"

//export engine_bootstrap_install_seeds
func engine_bootstrap_install_seeds(out unsafe.Pointer, outLen C.int) C.int {
	body, err := BootstrapInstallSeeds()
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_bootstrap_refresh
func engine_bootstrap_refresh(timeoutMs C.int, out unsafe.Pointer, outLen C.int) C.int {
	body, err := BootstrapRefresh(int(timeoutMs))
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_bootstrap_status
func engine_bootstrap_status(out unsafe.Pointer, outLen C.int) C.int {
	body, err := BootstrapStatus()
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}
