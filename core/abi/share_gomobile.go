//go:build gomobile

package abi

// Phase 1C extensions to the DaalCore gomobile facade. All functions
// return JSON strings (or error) so the Java/Kotlin side handles parsing.

func (h *DaalCore) ShareBegin(routeIDsCSV string, includeLAN bool, staticQRURI string) (string, error) {
	return ShareBegin(routeIDsCSV, includeLAN, staticQRURI)
}

func (h *DaalCore) ShareEnd(sessionID string) error { return ShareEnd(sessionID) }

func (h *DaalCore) ShareBrowse(timeoutMs int) (string, error) { return ShareBrowse(timeoutMs) }

func (h *DaalCore) SharePull(host string, port int, pin, sessionID string) (string, error) {
	return SharePull(host, port, pin, sessionID)
}

func (h *DaalCore) SharePullURL(httpsURL, pin, sessionID string) (string, error) {
	return SharePullURL(httpsURL, pin, sessionID)
}

func (h *DaalCore) FountainNextFrame(sessionID string) (string, error) {
	return FountainNextFrame(sessionID)
}

func (h *DaalCore) FountainFeedFrame(sessionID, frameB64 string) (string, error) {
	return FountainFeedFrame(sessionID, frameB64)
}

func (h *DaalCore) UriDetect(text string) (string, error) { return URIDetect(text) }

func (h *DaalCore) UriImport(rawURI string) (string, error) { return URIImport(rawURI) }
