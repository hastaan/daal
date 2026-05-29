package uri

import (
	"encoding/json"
	"fmt"
)

// SIP008 JSON: { "version":1, "servers":[{"id","remarks","server","server_port","password","method"...}] }
type sip008Doc struct {
	Version int           `json:"version"`
	Servers []sip008Entry `json:"servers"`
}

type sip008Entry struct {
	ID         string `json:"id"`
	Remarks    string `json:"remarks"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"plugin_opts,omitempty"`
}

func parseSIP008(body []byte) ([]Profile, Provenance, error) {
	var doc sip008Doc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, Provenance{}, err
	}
	if len(doc.Servers) == 0 {
		return nil, Provenance{Scheme: "sip008"}, ErrNoMatch
	}
	profiles := make([]Profile, 0, len(doc.Servers))
	for _, s := range doc.Servers {
		if s.Server == "" || s.ServerPort == 0 {
			continue
		}
		out := map[string]any{
			"type":        "shadowsocks",
			"server":      s.Server,
			"server_port": s.ServerPort,
			"method":      s.Method,
			"password":    s.Password,
		}
		if s.Plugin != "" {
			out["plugin"] = s.Plugin
			if s.PluginOpts != "" {
				out["plugin_opts"] = s.PluginOpts
			}
		}
		profiles = append(profiles, Profile{
			TransportFamily: "shadowsocks",
			Outbound:        out,
			Tag:             s.Remarks,
		})
	}
	if len(profiles) == 0 {
		return nil, Provenance{Scheme: "sip008"}, fmt.Errorf("sip008: no usable servers")
	}
	return profiles, Provenance{Scheme: "sip008"}, nil
}
