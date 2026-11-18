package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// `wb storage` is ordinary static hosting on the public internet — the
// thing a publisher's freshness mirrors and pack URL point at (an R2
// bucket's public URL, a GitHub Pages site, a CDN path). It is reachable
// from the insider's network WITHOUT a tunnel, through the censor, which
// is the situation the freshness path exists for.
//
// It serves <dir>/<host>/<path> for whatever Host is asked, over TLS with
// a certificate for whatever SNI is asked (issued by the lab CA, like the
// rest of the lab's public internet). Every request is logged to
// storage-requests.jsonl so a check can say who fetched what, from where.
//
// What it stands in for and does NOT exercise: the providers' upload APIs
// (R2's S3 endpoint, GitHub's contents API). The publisher's signed
// document is put here by the rig, not by `publish-freshness`'s uploader.
const (
	NSStorage       = "storage"
	StorageIP       = "198.19.7.2"
	CensorStorageIP = "198.19.7.1"
	CensorDevStore  = "to-storage"
)

func cmdStorage(args []string) int {
	fs := flag.NewFlagSet("storage", flag.ExitOnError)
	run := fs.String("run-dir", "", "")
	dir := fs.String("dir", "", "document root: <dir>/<host>/<path>")
	_ = fs.Parse(args)
	caCert, caKey, err := loadCA(*run)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	logf, err := os.OpenFile(filepath.Join(*run, "storage-requests.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	var mu sync.Mutex
	cache := map[string]*tls.Certificate{}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			name := hello.ServerName
			if name == "" {
				name = "storage.invalid"
			}
			if c, ok := cache[name]; ok {
				return c, nil
			}
			c, err := mintLeaf(caCert, caKey, name)
			if err == nil {
				cache[name] = c
			}
			return c, err
		},
	}
	ln, err := tls.Listen("tcp4", net.JoinHostPort(StorageIP, "443"), cfg)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	fmt.Println("storage: listening")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(strings.Split(r.Host, ":")[0])
		path := filepath.Join(*dir, filepath.FromSlash(filepath.Clean("/"+host+"/"+r.URL.Path)))
		status := 200
		body, err := os.ReadFile(path)
		if err != nil || !strings.HasPrefix(path, filepath.Clean(*dir)+string(os.PathSeparator)) {
			status = 404
			http.NotFound(w, r)
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
		}
		from, _, _ := net.SplitHostPort(r.RemoteAddr)
		line, _ := json.Marshal(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "from": from, "host": host,
			"path": r.URL.Path, "status": status, "bytes": len(body), "user_agent": r.UserAgent()})
		mu.Lock()
		logf.Write(append(line, '\n'))
		mu.Unlock()
	})}
	log.Fatal(srv.Serve(ln))
	return 1
}

// StorageRequest is one line of storage-requests.jsonl.
type StorageRequest struct {
	From   string `json:"from"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

func StorageRequests(p Paths) []StorageRequest {
	body, _ := os.ReadFile(filepath.Join(p.Run, "storage-requests.jsonl"))
	var out []StorageRequest
	for _, line := range strings.Split(string(body), "\n") {
		var q StorageRequest
		if json.Unmarshal([]byte(line), &q) == nil && q.Host != "" {
			out = append(out, q)
		}
	}
	return out
}
