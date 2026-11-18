package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
)

// The target is "a site the censor blocks": the thing the insider is
// trying to reach. It exists to make a pass MEAN something:
//
//	GET /whoami?nonce=N   → {"nonce":N,"remote":"<ip the request came from>"}
//	GET /blob?seed=S&size=B → B deterministic bytes (the probe regenerates
//	                          them and compares the SHA-256)
//	POST /sink            → {"bytes":n,"sha256":…,"remote":…} of the body:
//	                          the UPLOAD direction, verified by the far end
//	UDP :7                → echoes the datagram prefixed with the sender's ip
//
// The same process is the public resolvers the phone is configured with
// (resolver.go): they are part of what "the internet" means to an app.
//
// `remote` is the path proof: a fetch that really went through the relay
// arrives from the relay's egress address and from nowhere else.

// blob returns size deterministic pseudo-random bytes for seed.
func blob(seed uint64, size int) []byte {
	r := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	out := make([]byte, size)
	for i := 0; i+8 <= size; i += 8 {
		v := r.Uint64()
		for j := 0; j < 8; j++ {
			out[i+j] = byte(v >> (8 * j))
		}
	}
	return out
}

func blobSum(seed uint64, size int) string {
	s := sha256.Sum256(blob(seed, size))
	return hex.EncodeToString(s[:])
}

func cmdTarget(args []string) int {
	fs := flag.NewFlagSet("target", flag.ExitOnError)
	listen := fs.String("listen", TargetIP, "address to serve on")
	_ = fs.Parse(args)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"nonce": r.URL.Query().Get("nonce"), "remote": host})
	})
	mux.HandleFunc("GET /blob", func(w http.ResponseWriter, r *http.Request) {
		seed, _ := strconv.ParseUint(r.URL.Query().Get("seed"), 10, 64)
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		if size <= 0 || size > 64<<20 {
			http.Error(w, "size", 400)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(blob(seed, size))
	})

	mux.HandleFunc("POST /sink", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(r.Body, 64<<20))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"bytes": n, "sha256": hex.EncodeToString(h.Sum(nil)), "remote": host})
	})
	servePublicDNS()

	pc, err := net.ListenPacket("udp", net.JoinHostPort(*listen, "7"))
	if err != nil {
		log.Fatalf("target: udp: %v", err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(from.String())
			_, _ = pc.WriteTo(append([]byte(host+"|"), buf[:n]...), from)
		}
	}()
	ln, err := net.Listen("tcp", net.JoinHostPort(*listen, "80"))
	if err != nil {
		log.Fatalf("target: tcp: %v", err)
	}
	fmt.Println("target: listening")
	log.Fatal(http.Serve(ln, mux))
	return 1
}
