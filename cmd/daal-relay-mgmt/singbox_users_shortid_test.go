package main

import (
	"encoding/json"
	"testing"
)

// Revoking one recipient must remove that recipient's REALITY
// short_id, not "the last one". appendVLESSUser pairs users[i] with
// short_id[i], so the index is the only correct handle.
//
// The old code truncated the list to the new user count: revoking r1
// (index 0) from [r1, r2] left short_id [A] — r2, still live, lost the
// credential its client presents on the primary 443/tcp transport,
// while the revoked r1's short_id stayed in the accepted set.
func TestRemoveVLESSUser_DropsTheRevokedUsersShortID(t *testing.T) {
	const cfg = `{"inbounds":[
      {"type":"vless","tag":"vless-in","users":[
        {"uuid":"u-1","name":"r1","flow":"xtls-rprx-vision"},
        {"uuid":"u-2","name":"r2","flow":"xtls-rprx-vision"},
        {"uuid":"u-3","name":"r3","flow":"xtls-rprx-vision"}],
       "tls":{"reality":{"short_id":["aaaaaaaa","bbbbbbbb","cccccccc"]}}}]}`

	var doc map[string]any
	if err := json.Unmarshal([]byte(cfg), &doc); err != nil {
		t.Fatal(err)
	}
	if !removeVLESSUser(doc, "r1") {
		t.Fatal("removeVLESSUser reported no change")
	}

	in := findInboundByTag(doc, tagVLESS)
	users, _ := in["users"].([]any)
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2", len(users))
	}
	reality := in["tls"].(map[string]any)["reality"].(map[string]any)
	sids, _ := reality["short_id"].([]any)
	got := make([]string, 0, len(sids))
	for _, s := range sids {
		got = append(got, s.(string))
	}
	// r2 keeps bbbbbbbb, r3 keeps cccccccc; only r1's aaaaaaaa goes.
	if len(got) != 2 || got[0] != "bbbbbbbb" || got[1] != "cccccccc" {
		t.Fatalf("short_id = %v, want [bbbbbbbb cccccccc]", got)
	}
}

// Same for a middle removal, where truncation happens to keep the right
// count and still revokes the wrong credential.
func TestRemoveVLESSUser_MiddleRemovalKeepsTheSurvivorsCredentials(t *testing.T) {
	const cfg = `{"inbounds":[
      {"type":"vless","tag":"vless-in","users":[
        {"uuid":"u-1","name":"r1"},
        {"uuid":"u-2","name":"r2"},
        {"uuid":"u-3","name":"r3"}],
       "tls":{"reality":{"short_id":["aaaaaaaa","bbbbbbbb","cccccccc"]}}}]}`

	var doc map[string]any
	if err := json.Unmarshal([]byte(cfg), &doc); err != nil {
		t.Fatal(err)
	}
	if !removeVLESSUser(doc, "r2") {
		t.Fatal("removeVLESSUser reported no change")
	}
	in := findInboundByTag(doc, tagVLESS)
	reality := in["tls"].(map[string]any)["reality"].(map[string]any)
	sids, _ := reality["short_id"].([]any)
	if len(sids) != 2 || sids[0] != "aaaaaaaa" || sids[1] != "cccccccc" {
		t.Fatalf("short_id = %v, want [aaaaaaaa cccccccc]", sids)
	}
}
