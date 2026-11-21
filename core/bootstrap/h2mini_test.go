package bootstrap

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// The decoder against RFC 7541 Appendix C.4 (requests with Huffman
// coding and a dynamic table that carries across blocks).
func TestHPACKDecode_RFC7541C4(t *testing.T) {
	blocks := []string{
		"828684418cf1e3c2e5f23a6ba0ab90f4ff",
		"828684be5886a8eb10649cbf",
		"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
	}
	want := [][]string{
		{":method=GET", ":scheme=http", ":path=/", ":authority=www.example.com"},
		{":method=GET", ":scheme=http", ":path=/", ":authority=www.example.com", "cache-control=no-cache"},
		{":method=GET", ":scheme=https", ":path=/index.html", ":authority=www.example.com", "custom-key=custom-value"},
	}
	d := newHPACKDecoder(4096)
	for i, h := range blocks {
		b, _ := hex.DecodeString(h)
		got, err := d.decode(b, 1<<16)
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		var s []string
		for _, f := range got {
			s = append(s, f.name+"="+f.value)
		}
		if fmt.Sprint(s) != fmt.Sprint(want[i]) {
			t.Fatalf("block %d: %v", i, s)
		}
	}
	if d.size != 164 {
		t.Fatalf("table size %d, RFC says 164", d.size)
	}
}

// Round trips against Go's own encoder (what an h2 server built on it
// sends): Huffman, incremental indexing, eviction, table size updates.
func TestHPACKDecode_AgainstGoEncoder(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.SetMaxDynamicTableSizeLimit(256)
	enc.SetMaxDynamicTableSize(256)
	d := newHPACKDecoder(65536)
	for round := 0; round < 40; round++ {
		buf.Reset()
		fields := []hpack.HeaderField{
			{Name: ":status", Value: fmt.Sprint([]int{200, 302, 404}[round%3])},
			{Name: "location", Value: fmt.Sprintf("https://script.googleusercontent.com/macros/echo?user_content_key=%d", round)},
			{Name: "content-type", Value: "text/plain; charset=utf-8"},
			{Name: "x-custom-" + fmt.Sprint(round%5), Value: string(bytes.Repeat([]byte{byte('a' + round%26)}, round))},
			{Name: "set-cookie", Value: "secret", Sensitive: true},
		}
		for _, f := range fields {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		got, err := d.decode(buf.Bytes(), 1<<16)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if len(got) != len(fields) {
			t.Fatalf("round %d: %d fields", round, len(got))
		}
		for i := range fields {
			if got[i].name != fields[i].Name || got[i].value != fields[i].Value {
				t.Fatalf("round %d field %d: %q=%q", round, i, got[i].name, got[i].value)
			}
		}
	}
}

func TestHPACKHuffman_AllBytes(t *testing.T) {
	var in []byte
	for i := 0; i < 256; i++ {
		in = append(in, byte(i))
	}
	enc := hpack.AppendHuffmanString(nil, string(in))
	got, err := hpackHuffmanDecode(enc)
	if err != nil || got != string(in) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestHPACKDecode_Hostile(t *testing.T) {
	for name, h := range map[string]string{
		"index 0":                 "80",
		"index past the tables":   "ff00",
		"string past the block":   "0085616263",
		"truncated integer":       "ff",
		"huge integer":            "7fffffffffff0f",
		"bad huffman padding":     "0081" + "00", // one byte of zero bits as padding... first name literal Huffman
		"table size over limit":   "3fe1ff03",
		"size update after field": "823f00",
	} {
		b, _ := hex.DecodeString(h)
		d := newHPACKDecoder(4096)
		if _, err := d.decode(b, 1<<16); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// EOS inside a string.
	if _, err := hpackHuffmanDecode([]byte{0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Error("EOS accepted")
	}
	// A header list over the bound.
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: "x", Value: string(bytes.Repeat([]byte("y"), 2000))})
	d := newHPACKDecoder(4096)
	if _, err := d.decode(buf.Bytes(), 1000); err == nil {
		t.Error("an oversized header list was accepted")
	}
}

func TestH2RequestHeaders_DecodeBack(t *testing.T) {
	b := h2RequestHeaders("script.google.com", "/macros/s/x/exec?k=y")
	d := newHPACKDecoder(4096)
	got, err := d.decode(b, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{":method=GET", ":authority=script.google.com", ":scheme=https", ":path=/macros/s/x/exec?k=y"}
	for i, w := range want {
		if got[i].name+"="+got[i].value != w {
			t.Fatalf("field %d: %v", i, got[i])
		}
	}
	if len(d.dyn) != 0 {
		t.Fatal("the request put entries in the server's dynamic table")
	}
}
