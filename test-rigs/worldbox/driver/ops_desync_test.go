package main

import (
	"bytes"
	"testing"
)

func TestNameCutVerdict(t *testing.T) {
	const name = "www.cover.example"
	hello := []byte("\x16\x03\x01..........." + name + "......tail")
	at := bytes.Index(hello, []byte(name))
	flow := func(cuts ...int) flowData {
		var fd flowData
		prev := 0
		for _, c := range append(cuts, len(hello)) {
			fd.Payloads = append(fd.Payloads, hello[prev:c])
			fd.Sizes = append(fd.Sizes, c-prev)
			prev = c
		}
		return fd
	}
	other := flowData{Sizes: []int{3}, Payloads: [][]byte{[]byte("abc")}}
	// Two records split mid-name, cut at the record boundary.
	payload := []byte("....." + name + ".....")
	cut := 5 + 8
	rec := func(b []byte) []byte { return append([]byte{0x16, 3, 1, byte(len(b) >> 8), byte(len(b))}, b...) }
	r1, r2 := rec(payload[:cut]), rec(payload[cut:])
	records := flowData{Sizes: []int{len(r1), len(r2)}, Payloads: [][]byte{r1, r2}}
	oneRecord := flowData{Sizes: []int{len(payload) + 5}, Payloads: [][]byte{rec(payload)}}
	cases := []struct {
		preset string
		flows  []flowData
		want   string
	}{
		{"sni-cut", []flowData{flow(1, at+8)}, Pass},
		{"sni-cut", []flowData{flow(1, at+len(name)+2)}, Fail}, // the name whole in packet 2
		{"sni-cut", []flowData{flow(1, 4, at+8)}, Pass},
		{"sni-cut", []flowData{flow(at+3, at+len(name)+2)}, Fail}, // whole in packets 1+2 joined
		{"chain", []flowData{flow(at+3, at+len(name)+2)}, Pass},   // chain claims one packet, not two
		{"chain", []flowData{flow(1, at, at+6, at+12, at+len(name))}, Pass},
		{"chain", []flowData{flow(1, at, at+len(name))}, Fail}, // one piece is the whole name
		{"tlsrec-sni", []flowData{other}, Skipped},
		{"tlsrec-sni", []flowData{records}, Pass},
		{"tlsrec-sni", []flowData{oneRecord}, Fail},
		{"split1", []flowData{flow(1)}, Skipped},
		{"sni-cut", nil, Skipped},
	}
	for i, c := range cases {
		got, note, _ := nameCutVerdict(c.preset, c.flows, name)
		if got != c.want {
			t.Errorf("case %d (%s): %s %q, want %s", i, c.preset, got, note, c.want)
		}
	}
}
