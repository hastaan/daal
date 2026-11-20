package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The lab's ECH key: what Cloudflare's edge holds for every zone that
// has ECH on (one shared configuration, outer name cloudflare-ech.com).
// Generated once per world (WriteLabECH); the edge (fakecdn.go) serves
// with it, the lab's DoH (fakecf_api.go) publishes it in each proxied
// hostname's HTTPS record, and the raw probes can offer it
// (`rawprobe --ech`). It is a test key with no meaning outside the
// world it was made for.
//
// Format (draft-ietf-tls-esni, version 0xfe0d), the one Go's TLS stack
// and sing-box read:
//
//	ECHConfigList  uint16 length, ECHConfig…
//	ECHConfig      uint16 version=0xfe0d, uint16 length, contents:
//	  config_id u8 · kem_id u16 (X25519 0x0020) · public_key <u16> ·
//	  cipher_suites <u16> (kdf u16, aead u16)… · maximum_name_length u8 ·
//	  public_name <u8> · extensions <u16>
const (
	echConfigFile = "lab-ech-config.bin"  // ECHConfigList (what clients are given)
	echSingleFile = "lab-ech-single.bin"  // the one ECHConfig in it (what Go's server wants)
	echKeyFile    = "lab-ech-private.key" // X25519 private key, raw 32 bytes
	echVersion    = 0xfe0d
)

// buildECHConfig returns one ECHConfig for an X25519 public key.
func buildECHConfig(id byte, pub []byte, publicName string) []byte {
	var c []byte
	c = append(c, id)
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	suites := []uint16{0x0001, 0x0001, 0x0001, 0x0003} // HKDF-SHA256 with AES-128-GCM, and with ChaCha20-Poly1305
	c = binary.BigEndian.AppendUint16(c, uint16(2*len(suites)))
	for _, s := range suites {
		c = binary.BigEndian.AppendUint16(c, s)
	}
	c = append(c, 0) // maximum_name_length: 0 = let the client pad as it likes
	c = append(c, byte(len(publicName)))
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0) // no extensions
	out := binary.BigEndian.AppendUint16(nil, echVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c)))
	return append(out, c...)
}

func echConfigList(configs ...[]byte) []byte {
	var body []byte
	for _, c := range configs {
		body = append(body, c...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
}

// WriteLabECH makes the world's ECH key once.
func WriteLabECH(run string) error {
	if _, err := os.Stat(filepath.Join(run, echKeyFile)); err == nil {
		return nil
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	single := buildECHConfig(7, k.PublicKey().Bytes(), ECHPublicName)
	for name, body := range map[string][]byte{echSingleFile: single, echConfigFile: echConfigList(single), echKeyFile: k.Bytes()} {
		if err := os.WriteFile(filepath.Join(run, name), body, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// LabECH reads the world's ECH material.
func LabECH(run string) (list, single, priv []byte, err error) {
	if list, err = os.ReadFile(filepath.Join(run, echConfigFile)); err != nil {
		return
	}
	if single, err = os.ReadFile(filepath.Join(run, echSingleFile)); err != nil {
		return
	}
	priv, err = os.ReadFile(filepath.Join(run, echKeyFile))
	return
}

// ---- DNS: the HTTPS record a DoH resolver answers with ------------------

// dnsQuestion reads the single question of a DNS query.
func dnsQuestion(q []byte) (id uint16, name string, qtype uint16, end int, err error) {
	if len(q) < 12 {
		return 0, "", 0, 0, errors.New("dns: short query")
	}
	id = binary.BigEndian.Uint16(q)
	if binary.BigEndian.Uint16(q[4:]) != 1 {
		return 0, "", 0, 0, errors.New("dns: want exactly one question")
	}
	off := 12
	var labels []string
	for {
		if off >= len(q) {
			return 0, "", 0, 0, errors.New("dns: truncated name")
		}
		l := int(q[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(q) {
			return 0, "", 0, 0, errors.New("dns: bad label")
		}
		labels = append(labels, string(q[off:off+l]))
		off += l
	}
	if off+4 > len(q) {
		return 0, "", 0, 0, errors.New("dns: truncated question")
	}
	qtype = binary.BigEndian.Uint16(q[off:])
	return id, strings.ToLower(strings.Join(labels, ".")), qtype, off + 4, nil
}

// dnsHTTPSAnswer answers query with one HTTPS record (priority 1, target
// ".", alpn h2+http/1.1, and ech when given), or with an empty NOERROR
// answer when ech and alpn are both absent (nameExists) or NXDOMAIN.
func dnsHTTPSAnswer(query []byte, nameExists bool, ech []byte) ([]byte, error) {
	id, _, qtype, end, err := dnsQuestion(query)
	if err != nil {
		return nil, err
	}
	flags := uint16(0x8180) // response, RD, RA
	an := uint16(0)
	if !nameExists {
		flags |= 3
	} else if qtype == 65 {
		an = 1
	}
	msg := binary.BigEndian.AppendUint16(nil, id)
	msg = binary.BigEndian.AppendUint16(msg, flags)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint16(msg, an)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = append(msg, query[12:end]...)
	if an == 0 {
		return msg, nil
	}
	var rd []byte
	rd = binary.BigEndian.AppendUint16(rd, 1) // ServiceMode
	rd = append(rd, 0)                        // target "."
	alpn := []byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	rd = binary.BigEndian.AppendUint16(rd, 1)
	rd = binary.BigEndian.AppendUint16(rd, uint16(len(alpn)))
	rd = append(rd, alpn...)
	if len(ech) > 0 {
		rd = binary.BigEndian.AppendUint16(rd, 5)
		rd = binary.BigEndian.AppendUint16(rd, uint16(len(ech)))
		rd = append(rd, ech...)
	}
	msg = append(msg, 0xc0, 12) // the question's name
	msg = binary.BigEndian.AppendUint16(msg, 65)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint32(msg, 300)
	if len(rd) > 0xffff {
		return nil, fmt.Errorf("dns: rdata too long")
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rd)))
	return append(msg, rd...), nil
}
