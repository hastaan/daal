package uri

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// parseTorBridges accepts a list of plain Tor bridge lines, one per line.
// Examples:
//
//	obfs4 1.2.3.4:443 ABCDEF... cert=...iat-mode=0
//	webtunnel 5.6.7.8:443 1234... url=https://example.com/path
//
// These map to sing-box "torbridge" outbounds (used as inputs to a
// tor outbound; we wrap each as a single sing-box outbound dict so the
// engine driver can route it through the embedded tor binary in V2).
func parseTorBridges(body []byte) ([]Profile, Provenance, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	prov := Provenance{Scheme: "tor-bridge"}
	var profiles []Profile
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip optional "Bridge " prefix.
		line = strings.TrimPrefix(line, "Bridge ")
		fields := strings.Fields(line)
		if len(fields) < 3 {
			prov.WarningCount++
			continue
		}
		transport := fields[0]
		host, port, err := splitEndpoint(fields[1])
		if err != nil {
			prov.WarningCount++
			continue
		}
		out := map[string]any{
			"type":        "tor-bridge",
			"transport":   transport,
			"server":      host,
			"server_port": port,
			"fingerprint": fields[2],
		}
		extras := map[string]string{}
		for _, kv := range fields[3:] {
			idx := strings.Index(kv, "=")
			if idx < 0 {
				continue
			}
			extras[kv[:idx]] = kv[idx+1:]
		}
		if len(extras) > 0 {
			extrasAny := make(map[string]any, len(extras))
			for k, v := range extras {
				extrasAny[k] = v
			}
			out["params"] = extrasAny
		}
		profiles = append(profiles, Profile{
			TransportFamily: "tor-bridge",
			Outbound:        out,
			Tag:             fmt.Sprintf("tor-%s-%s:%d", transport, host, port),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, prov, err
	}
	if len(profiles) == 0 {
		return nil, prov, ErrNoMatch
	}
	_ = strconv.Itoa
	return profiles, prov, nil
}
