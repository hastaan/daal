package freshness

// canonical.go holds the canonical-JSON writer shared by the
// freshness document, the mirror document and the sub-key cert
// walker.
//
// The implementation mirrors bundle.writeCanonical and
// publisher.canonicalJSONExcluding byte-for-byte: sorted object
// keys, no insignificant whitespace, integral floats printed as
// integers. Any divergence here is a signature that verifies on
// one side of the project and not the other, which is why it is
// a copy of a locked algorithm rather than a new one.
//
// NOTE ON NUMBERS: values arrive here as encoding/json's `any`,
// so every JSON number is a float64. Integers above 2^53-1 do not
// round-trip; the document's `sequence` is bounded at build time
// for exactly this reason (see maxSequence).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

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
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("freshness: unsupported value type %T", v)
	}
	return nil
}
