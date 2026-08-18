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

// expectedSPKI is the sender's published `spki=` TXT value. Passing it
// empty does NOT mean "skip the check" — SharePull refuses.
//
// The error branch returns -1 rather than copying an empty body out. The
// previous code had identical `if err != nil` and success branches, so a
// refused pull and a successful one were indistinguishable to the host:
// both wrote "" and returned 0. Wiring that through to a GUI would have
// rendered a failed, unverified pull as an empty-but-fine result.
//
//export engine_share_pull
func engine_share_pull(host *C.char, port C.int, pin, sessionID, expectedSPKI *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SharePull(C.GoString(host), int(port), C.GoString(pin), C.GoString(sessionID), C.GoString(expectedSPKI))
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

// shareURI is either `daalshare://lan?u=..&p=..&s=..` or a bare
// `https://<private-ip>:<port>/bundle.sbp#spki=..`. The SPKI pin rides
// inside the URI, so there is no unpinned spelling of this call.
//
//export engine_share_pull_url
func engine_share_pull_url(shareURI, pin, sessionID *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SharePullURL(C.GoString(shareURI), C.GoString(pin), C.GoString(sessionID))
	if err != nil {
		return -1
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
