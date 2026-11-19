// Command fakeworld runs a fakeworld.World for a test written in
// another language (the Rust shell's end-to-end tests). It prints one
// JSON line — {"proxy","ca_file","control"} — and serves until its
// stdin closes, so it dies with the test that started it.
//
//	fakeworld -dir DIR -token-file F [-families anytls,shadowsocks]
//
// `fakeworld fountain-decode` is the receiving phone's QR decoder (the
// same daal/bundle-go/fountain decoder core/share runs in the engine):
// frames on stdin, one base64url frame per line, the decoded file on
// stdout as standard base64 — exactly what FountainFeedFrame hands the
// shell as `sealed_b64`.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"daal/bundle-go/fountain"
	"daal/publisher/deploy/e2e/fakeworld"
)

func fountainDecode() int {
	dec := fountain.NewDecoder()
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(sc.Text()))
		if err != nil {
			fmt.Fprintln(os.Stderr, "fountain-decode:", err)
			return 1
		}
		payload, done, err := dec.Add(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fountain-decode:", err)
			return 1
		}
		if done {
			fmt.Println(base64.StdEncoding.EncodeToString(payload))
			return 0
		}
	}
	fmt.Fprintln(os.Stderr, "fountain-decode: frames ran out before the file was complete")
	return 1
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "fountain-decode" {
		os.Exit(fountainDecode())
	}
	dir := flag.String("dir", "", "directory for the CA file")
	tokenFile := flag.String("token-file", "", "the API token the account accepts")
	families := flag.String("families", "anytls", "families the boxes serve")
	flag.Parse()
	tok, err := os.ReadFile(*tokenFile)
	if err != nil || *dir == "" {
		fmt.Fprintln(os.Stderr, "fakeworld: -dir and a readable -token-file are required")
		os.Exit(2)
	}
	w, err := fakeworld.New(*dir, strings.TrimSpace(string(tok)), strings.Split(*families, ","))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakeworld:", err)
		os.Exit(1)
	}
	line, _ := json.Marshal(w.Endpoints())
	fmt.Println(string(line))
	_, _ = io.Copy(io.Discard, os.Stdin)
	w.Close()
}
