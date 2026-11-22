package cloudflare

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"daal/publisher/deploy/relayports"
)

// DoorRequest is the body of the relay's `POST /cdn` (daal-relay-mgmt,
// cmd/daal-relay-mgmt/singbox_cdn.go): it installs the Origin CA
// certificate and key and the origin-pull CA on the box and turns the
// ws-cdn-in inbound on, or turns it off again.
//
// The box keeps its own copy of this type (separate module). The two
// must agree field for field; cmd/daal-relay-mgmt's tests and this
// package's tests both pin the JSON names.
//
// It carries a private key. It travels only inside the management
// session (TLS pinned to the relay, every request signed) and is never
// written to disk by the publisher: BuildDoorEnable reads the key file
// the provisioning step wrote and the caller drops the request after
// sending it.
type DoorRequest struct {
	Action        string `json:"action"` // "enable" | "disable"
	Port          int    `json:"port,omitempty"`
	WSPath        string `json:"ws_path,omitempty"`
	OriginCertPEM string `json:"origin_cert_pem,omitempty"`
	OriginKeyPEM  string `json:"origin_key_pem,omitempty"`
	AOPCACertPEM  string `json:"aop_ca_pem,omitempty"`
	// EdgeRanges are the Cloudflare ranges the relay opens its box
	// firewall to for the door's port (FrontRecord.EdgeRanges).
	EdgeRanges []string `json:"edge_ranges,omitempty"`
}

// BuildDoorEnable assembles the enable request from a FrontRecord and
// the files ProvisionFront wrote, and checks them first: the key must
// match the certificate, the certificate must cover the hostname, the
// origin-pull CA must be a CA, and there must be Cloudflare ranges for
// the box firewall (a door behind a closed box firewall carries nothing). A relay handed a broken pair would
// fail its next reload, which takes every route down, not only this one.
func BuildDoorEnable(rec *FrontRecord) (DoorRequest, error) {
	if rec == nil {
		return DoorRequest{}, errors.New("door: record required")
	}
	if !ValidWSPath(rec.OriginPath) {
		return DoorRequest{}, fmt.Errorf("door: bad ws path %q", rec.OriginPath)
	}
	port := rec.OriginPort
	if port == 0 {
		port = relayports.CDNOrigin.Port
	}
	certPEM, err := os.ReadFile(rec.OriginCACertPath)
	if err != nil {
		return DoorRequest{}, fmt.Errorf("door: read origin certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(rec.OriginCAPrivPath)
	if err != nil {
		return DoorRequest{}, fmt.Errorf("door: read origin key: %w", err)
	}
	caPEM, err := os.ReadFile(rec.AOPCACertPath)
	if err != nil {
		return DoorRequest{}, fmt.Errorf("door: read origin pull CA: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return DoorRequest{}, fmt.Errorf("door: origin certificate and key do not match: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return DoorRequest{}, fmt.Errorf("door: origin certificate: %w", err)
	}
	if err := leaf.VerifyHostname(rec.Hostname); err != nil {
		return DoorRequest{}, fmt.Errorf("door: origin certificate does not cover %s: %w", rec.Hostname, err)
	}
	if len(rec.EdgeRanges) == 0 {
		return DoorRequest{}, errors.New("door: the record has no Cloudflare ranges for the relay's box firewall (run cdn-provision again)")
	}
	blk, _ := pem.Decode(caPEM)
	if blk == nil {
		return DoorRequest{}, errors.New("door: origin pull CA is not PEM")
	}
	ca, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || !ca.IsCA {
		return DoorRequest{}, errors.New("door: origin pull CA is not a CA certificate")
	}
	return DoorRequest{
		Action:        "enable",
		Port:          port,
		WSPath:        rec.OriginPath,
		OriginCertPEM: string(certPEM),
		OriginKeyPEM:  string(keyPEM),
		AOPCACertPEM:  string(caPEM),
		EdgeRanges:    append([]string(nil), rec.EdgeRanges...),
	}, nil
}

// DoorDisable is the request that turns ws-cdn-in off and deletes the
// door's certificate files on the box.
func DoorDisable() DoorRequest { return DoorRequest{Action: "disable"} }
