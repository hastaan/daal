//go:build cshared

package abi

import "C"

import "unsafe"

//export engine_subscription_add
func engine_subscription_add(publisherFP, url, displayName *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SubscriptionAdd(C.GoString(publisherFP), C.GoString(url), C.GoString(displayName))
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_subscription_refresh
func engine_subscription_refresh(subscriptionID *C.char, timeoutMs C.int, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SubscriptionRefresh(C.GoString(subscriptionID), int(timeoutMs))
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_subscription_remove
func engine_subscription_remove(subscriptionID *C.char) C.int {
	if err := SubscriptionRemove(C.GoString(subscriptionID)); err != nil {
		return -1
	}
	return 0
}

//export engine_subscription_list
func engine_subscription_list(out unsafe.Pointer, outLen C.int) C.int {
	body, err := SubscriptionList()
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_revocation_refresh_all
func engine_revocation_refresh_all(timeoutMs C.int, out unsafe.Pointer, outLen C.int) C.int {
	body, err := RevocationRefreshAll(int(timeoutMs))
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_pointer_rotation_status
func engine_pointer_rotation_status(out unsafe.Pointer, outLen C.int) C.int {
	body, err := PointerRotationStatus()
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_diagnostics_explain
func engine_diagnostics_explain(out unsafe.Pointer, outLen C.int) C.int {
	body, err := DiagnosticsExplain()
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}
