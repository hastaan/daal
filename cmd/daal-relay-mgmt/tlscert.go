// Re-issuing the data-plane certificate on /rotate-tls.
//
// WHY. cloud-init mints /etc/daal/tls-cert.pem once, at first boot: the
// box's address as an iPAddress SAN plus ONE dNSName — the cover host the
// relay was provisioned with. Six of the seven families never look at a
// name in that certificate (they pin its key). naive does: it rides
// Chromium's network stack, which verifies a name, and after an address
// move (L3) the name it verifies — and shows on the wire as SNI — is
// that dNSName (bundle.NaiveVerificationName on the publisher's side).
//
// /rotate-tls exists to move the relay off a cover host that is being
// filtered. Before this file it moved REALITY's cover host and left the
// certificate alone, so after a later address move naive presented the
// OLD cover host: the one name the operator had just rotated away from,
// on the one address that was not yet blocked.
//
// WHAT. When /rotate-tls moves the cover host, the certificate is issued
// again:
//
//   - SAME KEY. Every signed endpoint commits to the SubjectPublicKeyInfo
//     pin (specs/relaypack-v1.md "Endpoint commitment"), and every
//     pinned family's pack carries that pin. A new key would kill every
//     pack in the field; the same key changes nothing for any of them.
//     tls-key.pem and tls-spki-sha256.b64 are not touched.
//   - the NEW cover host is the FIRST dNSName — the one a pack minted
//     from now on verifies against and presents;
//   - every dNSName the old certificate carried is KEPT, after it. A
//     naive pack minted before the rotation trusts the old certificate
//     and verifies an old name; the relay must still be that name or
//     every such pack dies with the rotation. (They keep presenting the
//     old name until their holder gets the new one — a re-minted file,
//     or the signed endpoint.)
//   - iPAddress SANs: EXACTLY the ones the old certificate carried, and
//     never an address the box was given since. This certificate is
//     served to anybody who opens a TLS connection to a pinned-family
//     port, with no credentials. An address bound later (/bind-address,
//     the L3 swap) is bound BECAUSE the earlier one is burned, and the
//     earlier one keeps answering: naming the fresh address here would
//     hand it to whoever probes the burned one. The price is that a
//     naive pack minted for a later-bound address verifies and presents
//     the cover host instead of putting no name on the wire - which is
//     what already happens after any address move not followed by a
//     cover-host move. No-SNI on a moved address would need a
//     certificate per listener, not one certificate listing everything.
//   - same subject, self-signed, the 90-day validity cloud-init uses
//     (Chromium's ceiling for a locally trusted root: see v2.yaml.tmpl).
//     Re-issuing therefore also renews.
//   - EXCEPT a subject that names the app. Relays provisioned before
//     2026-11-20 were minted with CN=daal-relay, and this certificate is
//     served to anybody who completes a handshake on 8444, 8445 or
//     443/udp: every such relay told every prober what it was. Such a
//     subject is replaced, once, by the neutral one cloud-init now
//     writes (neutralCommonName: the certificate's own first name). See
//     "THE PRICE" below.
//
// WHY THE SUBJECT IS OTHERWISE COPIED. A client that installed the OLD
// certificate as its root accepts the new one only because the new
// one's ISSUER is the old one's SUBJECT and it is signed by the same
// key: Chromium (and so Cronet, and so naive) finds a trusted root for a
// certificate by its issuer name, and a naive pack carries the
// certificate it was minted with, not a pin. The signed endpoint cannot
// deliver a new certificate (it commits to the key only). The
// end-to-end rig holds that (op:l2 old-pack, naive). Nothing else reads
// the name: the six other families pin the key, and Chromium matches
// hostnames in the SAN only.
//
// THE PRICE of retiring CN=daal-relay: a naive pack minted before the
// rename trusts a root whose name no longer issues anything, so it
// stops connecting (it fails closed: the handshake is refused, nothing
// is trusted that was not before). There is no way round it that keeps
// the name off the wire: a bridge certificate would carry the old name
// as its issuer, in the same handshake. The reply says so in
// `warnings` and names "tls_certificate_subject" in `changed`, so the
// publisher can tell the operator to send naive recipients a new link.
// Every other family is untouched (same key). In practice this branch
// is reached by no relay today: a relay's mgmt binary is fixed at first
// boot (there is no in-place upgrade), and a relay provisioned from a
// tree carrying this file was also given the neutral subject by
// cloud-init. It is here so a future upgrade path cannot carry the old
// name forward silently.
//
// FAILURE IS NOT FATAL TO THE ROTATION. L2 is the operator's answer to
// "the cover host is being filtered", usually under pressure. If the
// certificate cannot be re-issued the cover host still moves (which is
// what REALITY needs) and the reply says so in `warnings`: naive keeps
// the certificate, and the names, it had.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// dataPlaneCertValidity mirrors `-days 90` in v2.yaml.tmpl. Chromium
// refuses a locally trusted root valid for longer than its CA/B-Forum
// bracket for the issue date (200 days from 2026-03-15, 100 from
// 2027-03-15, 47 from 2029-03-15) with ERR_CERT_VALIDITY_TOO_LONG, and
// only naive notices. Shorten both to <= 47 before 2029-03-15.
const dataPlaneCertValidity = 90 * 24 * time.Hour

// maxCertDNSNames bounds how many past cover hosts a certificate
// carries. Each rotation adds one; the oldest are dropped past the cap.
// A pack old enough to verify a dropped name is more than this many
// rotations stale.
const maxCertDNSNames = 8

var errNoDataPlaneCert = errors.New("this relay has no data-plane certificate to re-issue")

// reissuedCertTemplate builds the certificate that replaces old when the
// cover host moves to coverHost. Pure: no clock, no randomness, no I/O.
// See the file comment for every choice in it.
func reissuedCertTemplate(old *x509.Certificate, coverHost string, serial *big.Int, now time.Time) *x509.Certificate {
	names := []string{coverHost}
	for _, n := range old.DNSNames {
		if n != "" && !contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) > maxCertDNSNames {
		names = names[:maxCertDNSNames]
	}
	// The addresses are copied, never read off the interface: see the
	// file comment (an address bound since first boot must not appear in
	// a certificate any prober can read).
	var ips []net.IP
	for _, ip := range old.IPAddresses {
		dup := false
		for _, have := range ips {
			dup = dup || have.Equal(ip)
		}
		if ip != nil && !dup {
			ips = append(ips, ip)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(dataPlaneCertValidity),
		DNSNames:              names,
		IPAddresses:           ips,
		BasicConstraintsValid: old.BasicConstraintsValid,
		IsCA:                  old.IsCA,
		KeyUsage:              old.KeyUsage,
		ExtKeyUsage:           old.ExtKeyUsage,
		SubjectKeyId:          old.SubjectKeyId,
		AuthorityKeyId:        old.SubjectKeyId,
	}
	if subjectNamesTheApp(old) {
		// Retired, once: see "THE PRICE" in the file comment. Self-signed,
		// so the issuer is this same neutral name.
		tmpl.Subject = pkix.Name{CommonName: neutralCommonName(names, ips)}
	} else {
		// Copied byte for byte: a client that trusts the old certificate
		// finds the new one's issuer by this name.
		tmpl.RawSubject = old.RawSubject
	}
	return tmpl
}

// maxCommonNameLen is X.509's upper bound on a CN (ub-common-name).
// cloud-init applies the same bound (openssl refuses longer).
const maxCommonNameLen = 64

// legacyCommonName is the one subject any template ever wrote
// (openssl req -subj "/CN=daal-relay", before v2.yaml.tmpl's neutral
// CN).
const legacyCommonName = "daal-relay"

// subjectNamesTheApp reports whether a certificate carries the legacy
// subject: exactly one attribute, a CN equal to "daal-relay". Exact, not
// a substring test: the neutral CN is the cover host, and a cover host
// that merely contains the letters (edaalat.example, a domain with
// "daal" in it) must not be renamed, because every rename ends every
// naive pack minted before it ("THE PRICE"). The parsed value is
// compared rather than RawSubject, because openssl writes the CN as a
// UTF8String and Go's encoder as a PrintableString.
func subjectNamesTheApp(c *x509.Certificate) bool {
	names := c.Subject.Names
	if len(names) != 1 || !names[0].Type.Equal(oidCommonName) {
		return false
	}
	v, ok := names[0].Value.(string)
	return ok && v == legacyCommonName
}

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// neutralCommonName is the subject v2.yaml.tmpl writes: the
// certificate's own first name — the cover host, or the address when
// there is none. It is what the ordinary self-signed recipe produces,
// differs per relay, and repeats a SAN, so it tells a prober nothing
// the certificate does not already say.
func neutralCommonName(dnsNames []string, ips []net.IP) string {
	for _, n := range dnsNames {
		if n != "" && len(n) <= maxCommonNameLen {
			return n
		}
	}
	for _, ip := range ips {
		if ip != nil {
			return ip.String()
		}
	}
	return "localhost"
}

// parseDataPlaneKey reads the private key cloud-init wrote. OpenSSL 3
// writes PKCS#8 ("PRIVATE KEY"); OpenSSL 1.1 wrote SEC1 ("EC PRIVATE
// KEY"). Both are read; nothing else is expected.
func parseDataPlaneKey(pemBytes []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no private key in the data-plane key file")
		}
		switch block.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			if s, ok := k.(crypto.Signer); ok {
				return s, nil
			}
			return nil, errors.New("data-plane key cannot sign")
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		}
	}
}

func samePublicKey(a, b crypto.PublicKey) bool {
	switch ak := a.(type) {
	case *ecdsa.PublicKey:
		return ak.Equal(b)
	case *rsa.PublicKey:
		return ak.Equal(b)
	case ed25519.PublicKey:
		return ak.Equal(b)
	}
	return false
}

// reissueDataPlaneCert replaces the certificate at s.tlsCertPath with
// one for coverHost (see the file comment), and returns the new PEM and
// a function that puts the old file back.
//
// changed=false with a nil error means the certificate already has
// coverHost as its first name: nothing was written. renamed=true means
// the re-issue also retired a subject that named the app, which ends
// every naive pack minted before it (see "THE PRICE").
//
// It must be called with cfgMu held, BEFORE the sing-box reload that
// applies the rotation, so one reload picks up the config and the
// certificate together; the caller runs restore if that reload fails.
func (s *server) reissueDataPlaneCert(coverHost string) (newPEM string, restore func(), changed, renamed bool, err error) {
	if s.tlsCertPath == "" || s.tlsKeyPath == "" {
		return "", nil, false, false, errNoDataPlaneCert
	}
	oldPEM, err := os.ReadFile(s.tlsCertPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, false, false, errNoDataPlaneCert
		}
		return "", nil, false, false, err
	}
	block, _ := pem.Decode(oldPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", nil, false, false, errors.New("the data-plane certificate file holds no certificate")
	}
	old, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, false, false, fmt.Errorf("parse the data-plane certificate: %w", err)
	}
	if len(old.DNSNames) > 0 && old.DNSNames[0] == coverHost {
		return string(oldPEM), nil, false, false, nil
	}
	keyPEM, err := os.ReadFile(s.tlsKeyPath)
	if err != nil {
		return "", nil, false, false, fmt.Errorf("read the data-plane key: %w", err)
	}
	key, err := parseDataPlaneKey(keyPEM)
	if err != nil {
		return "", nil, false, false, err
	}
	// The whole point is that the key does not move. If the key file is
	// not the certificate's key, re-issuing would silently change every
	// pin in the field: refuse.
	if !samePublicKey(key.Public(), old.PublicKey) {
		return "", nil, false, false, errors.New("the data-plane key file is not the key of the data-plane certificate; not re-issuing (it would change the pinned key)")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", nil, false, false, err
	}
	tmpl := reissuedCertTemplate(old, coverHost, serial, s.now())
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return "", nil, false, false, fmt.Errorf("sign the re-issued certificate: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	mode := os.FileMode(0o644)
	if st, serr := os.Stat(s.tlsCertPath); serr == nil {
		mode = st.Mode().Perm()
	}
	write := func(b []byte) error {
		tmp, err := os.CreateTemp(filepath.Dir(s.tlsCertPath), ".tls-cert-*.pem")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(b); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Chmod(mode); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(tmp.Name(), s.tlsCertPath)
	}
	if err := write(out); err != nil {
		return "", nil, false, false, fmt.Errorf("write the re-issued certificate: %w", err)
	}
	return string(out), func() { _ = write(oldPEM) }, true, subjectNamesTheApp(old), nil
}
