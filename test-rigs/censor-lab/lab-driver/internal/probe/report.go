package probe

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Forbidden field names that must NEVER appear at any nesting level in a probe report.
var forbidden = []string{
	"ip",
	"public_ip",
	"src_ip",
	"dst_ip",
	"latitude",
	"longitude",
	"location",
	"ssid",
	"bssid",
	"imsi",
	"imei",
	"hardware_id",
	"persistent_id",
	"device_id",
	"user_id",
	"url",
	"destination",
	"history",
}

// CheckPrivacy walks a parsed JSON document and rejects any forbidden key.
func CheckPrivacy(raw json.RawMessage) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	return walk(v, "")
}

func walk(v any, path string) error {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			lk := strings.ToLower(k)
			for _, bad := range forbidden {
				if lk == bad {
					return fmt.Errorf("forbidden field %q at %s", k, path)
				}
			}
			if err := walk(child, path+"/"+k); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range x {
			if err := walk(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
