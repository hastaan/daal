package importer

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"time"

	"daal/bundle-go/bundle"
)

func mapSourceType(bundleType string) string {
	switch bundleType {
	case "provider":
		return "trusted_provider"
	case "friend_share":
		return "friend_shared"
	case "emergency":
		return "official_bootstrap"
	default:
		return "manual"
	}
}

func modesFor(scarcity string) []string {
	switch bundle.ScarcityClass(scarcity) {
	case bundle.ScarcityEmergency, bundle.ScarcityLifelineOnly:
		return []string{"lifeline"}
	case bundle.ScarcityLow:
		return []string{"lifeline", "normal"}
	case bundle.ScarcityNormal:
		return []string{"lifeline", "normal"}
	case bundle.ScarcityBulkCapable:
		return []string{"lifeline", "normal", "bulk"}
	default:
		return []string{"normal"}
	}
}

func trustStateFromLevel(level string) string {
	switch level {
	case "official", "trusted_provider":
		return "trusted"
	case "tofu_friend":
		return "tofu"
	case "revoked":
		return "revoked"
	default:
		return "unknown"
	}
}

func hourBucket(t time.Time) string {
	return t.UTC().Truncate(time.Hour).Format("2006-01-02T15:04:05Z")
}

func classifyVerifyError(err error) string {
	switch err {
	case bundle.ErrFingerprintMismatch:
		return "publisher_key_changed"
	case bundle.ErrRevokedPublisher:
		return "publisher_revoked"
	case bundle.ErrRevokedRoute:
		return "publisher_revoked"
	case bundle.ErrExpiredBundle, bundle.ErrExpiredRoute:
		return "route_expired"
	case bundle.ErrInvalidEnum:
		return "bundle_corrupted"
	case bundle.ErrUnsafePath:
		return "bundle_corrupted"
	}
	return "bundle_signature_invalid"
}

func readSingleZipEntry(body []byte, name string) ([]byte, bool) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, false
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, false
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, false
			}
			return data, true
		}
	}
	return nil, false
}

// canonicalRotation re-emits a RotationChainDoc as canonical JSON with
// signature_hex stripped. Reserved for future strict chain verification;
// kept here so the file-of-truth lives next to RotationChainDoc.
func canonicalRotation(doc RotationChainDoc) []byte {
	raw, _ := json.Marshal(doc)
	var asMap map[string]any
	_ = json.Unmarshal(raw, &asMap)
	delete(asMap, "signature_hex")
	keys := make([]string, 0, len(asMap))
	for k := range asMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		switch v := asMap[k].(type) {
		case string:
			vb, _ := json.Marshal(v)
			buf.Write(vb)
		case float64:
			buf.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
		default:
			vb, _ := json.Marshal(v)
			buf.Write(vb)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes()
}
