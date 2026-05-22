//go:build cshared

package abi

import "C"

import (
	"unsafe"
)

//export engine_share_begin
func engine_share_begin(routeIDs *C.char, includeLAN C.int, qrURI *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := ShareBegin(C.GoString(routeIDs), includeLAN != 0, C.GoString(qrURI))
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_share_end
func engine_share_end(sessionID *C.char) C.int {
	if err := ShareEnd(C.GoString(sessionID)); err != nil {
		return -1
	}
	return 0
}

//export engine_share_browse
func engine_share_browse(timeoutMs C.int, out unsafe.Pointer, outLen C.int) C.int {
	body, err := ShareBrowse(int(timeoutMs))
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_share_pull
func engine_share_pull(host *C.char, port C.int, pin, sessionID *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SharePull(C.GoString(host), int(port), C.GoString(pin), C.GoString(sessionID))
	if err != nil {
		return copyOut(body, out, outLen)
	}
	return copyOut(body, out, outLen)
}

//export engine_share_pull_url
func engine_share_pull_url(httpsURL, pin, sessionID *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SharePullURL(C.GoString(httpsURL), C.GoString(pin), C.GoString(sessionID))
	if err != nil {
		return copyOut(body, out, outLen)
	}
	return copyOut(body, out, outLen)
}

//export engine_fountain_next_frame
func engine_fountain_next_frame(sessionID *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := FountainNextFrame(C.GoString(sessionID))
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_fountain_feed_frame
func engine_fountain_feed_frame(sessionID, frameB64 *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := FountainFeedFrame(C.GoString(sessionID), C.GoString(frameB64))
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_uri_detect
func engine_uri_detect(text *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := URIDetect(C.GoString(text))
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_uri_import
func engine_uri_import(rawURI *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := URIImport(C.GoString(rawURI))
	if err != nil {
		return copyOut(body, out, outLen)
	}
	return copyOut(body, out, outLen)
}
