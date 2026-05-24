package publisher

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// signCanonical signs the canonical-JSON form of v after stripping the
// signature field, and returns the lowercase-hex signature.
func signCanonical(v any, signatureField string, priv ed25519.PrivateKey) (string, error) {
	body, err := canonicalJSONExcluding(v, signatureField)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(priv, body)), nil
}

// verifyCanonical reverses signCanonical.
func verifyCanonical(v any, signatureField, signatureHex string, pub ed25519.PublicKey) error {
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex")
	}
	body, err := canonicalJSONExcluding(v, signatureField)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// canonicalJSONExcluding marshals v with json, then re-emits canonical JSON
// with the named top-level field stripped.
func canonicalJSONExcluding(v any, dropField string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if obj, ok := doc.(map[string]any); ok {
		delete(obj, dropField)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		if v == float64(int64(v)) {
			buf.WriteString(strconv.FormatInt(int64(v), 10))
		} else {
			buf.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
		}
	case string:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical json type %T", value)
	}
	return nil
}
