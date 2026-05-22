package netmem

import (
	"crypto/sha256"
	"encoding/hex"
)

// Kind enumerates the network kinds the engine distinguishes for
// per-network memory. Locked at v1.
type Kind string

const (
	KindWiFi    Kind = "wifi"
	KindCell    Kind = "cell"
	KindEth     Kind = "eth"
	KindUnknown Kind = "unknown"
)

// SentinelUnset is the network ID the engine starts on after Init,
// before the first engine_network_changed call. Treated as a
// real-but-empty network: writes are accepted but the blob is
// pruned by Sweep on the first hour boundary.
const SentinelUnset = "0000000000000000"

// HashID computes the stable network identifier the engine and the
// netmem store agree on. Output is the first 8 bytes of
// SHA-256(kind || "|" || carrier || "|" || ssid), hex-encoded.
//
// For cell networks, ssid is empty and the hash buckets by
// carrier. For ethernet, both carrier and ssid are empty; the hash
// is a constant per kind. For wifi, the ssid is the only
// distinguishing input; carrier may be empty on desktop.
//
// 8-byte truncation gives 2^32 buckets — overkill for a single
// device's lifetime network history. Locked at v1.
func HashID(kind Kind, carrier, ssid string) string {
	h := sha256.New()
	h.Write([]byte(string(kind)))
	h.Write([]byte("|"))
	h.Write([]byte(carrier))
	h.Write([]byte("|"))
	h.Write([]byte(ssid))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// IsValidKind reports whether k is one of the recognised network
// kinds. Used by ABI argument validation.
func IsValidKind(k Kind) bool {
	switch k {
	case KindWiFi, KindCell, KindEth, KindUnknown:
		return true
	}
	return false
}
