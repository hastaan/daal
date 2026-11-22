package relaypack

// share_links.go — "Links for other apps": standard share links for ONE
// person on a relay, so an iPhone or a second app (v2rayNG, Hiddify,
// Streisand, Shadowrocket, NekoBox) can use the relay as that person.
//
// THE RULE. A link is rendered only for a way in that another client can
// verify SAFELY from the link alone. Daal's own file pins the relay
// (REALITY key, SPKI pin, signed endpoint); a share link carries none of
// Daal's machinery, so it is worth exactly what its grammar can express:
//
//   - vless-reality: the REALITY public key IS the server authentication,
//     and every client in the list speaks pbk/sid/sni/fp. Rendered.
//   - hysteria2: LEFT OUT for now (needs_insecure). A pinSHA256 link
//     (hy2ShareLink, kept for later) most likely connects nowhere: the
//     Hysteria client checks the pin in VerifyPeerCertificate, which Go
//     runs only AFTER normal chain verification, so a self-signed leaf
//     fails before the pin is looked at. It comes back once one real
//     client is shown to connect with the pin alone. Never insecure=1.
//   - shadowsocks (2022): no TLS; both ends authenticate on the PSK pair.
//     Rendered when the relay serves it for this person.
//   - websocket-tls through Cloudflare: verified by the public CA chain
//     of the edge, so it is safe to verify — but a link has no ECH, so it
//     shows the relay's Cloudflare name to anyone watching. Rendered only
//     when the signed commitment allows a plain hello (PlainFallback).
//   - websocket-tls direct, naive, tuic, anytls: a self-signed leaf on a
//     bare address that no share-link grammar these apps share can pin.
//     Each would need "allow insecure", so each is LEFT OUT and reported.
//
// Every rendered link is first rendered as the client outbound Daal's own
// file would carry and held to the route's SIGNED endpoint
// (bundle.CheckOutbound / CDNClientOutbound), exactly as
// RewriteProfilesForRecipient does: a link for a relay that has moved
// since the pack was signed is an error, not a quietly wrong link.
//
// Links are credentials. Nothing here logs them, and no error carries one.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"daal/bundle-go/bundle"
)

// The ways a share link can name. "cdn" is the websocket-tls route
// fronted by Cloudflare; the direct websocket-tls route is its own way.
const (
	ShareWayReality     = "vless-reality"
	ShareWayHysteria2   = "hysteria2"
	ShareWayShadowsocks = "shadowsocks"
	ShareWayCDN         = "cdn"
)

// Why a way was left out. Stable codes; the host maps each to its copy.
const (
	// The way's grammar cannot pin this relay's self-signed certificate,
	// so another app could use it only with certificate checks off.
	LeftOutNeedsInsecure = "needs_insecure"
	// Something the link needs is not known here (this person's key for
	// the way, the relay's certificate, the door's path).
	LeftOutMissingMaterial = "missing_material"
	// The signed pack commits to no endpoint for the route, so there is
	// nothing to hold the link to.
	LeftOutNotSigned = "not_signed"
	// The way in through Cloudflare would show its name in the clear,
	// and the signed commitment does not allow that.
	LeftOutShowsCDNName = "shows_cdn_name"
	// No share-link format for this way exists.
	LeftOutNoLinkFormat = "no_link_format"
)

// ShareLink is one importable link. Way is one of the ShareWay* names.
type ShareLink struct {
	Way   string `json:"way"`
	Label string `json:"label"`
	Link  string `json:"link"`
}

// LeftOutWay is one way in that has no link, and why. Detail is an
// English sentence for logs and the CLI; it never carries a credential
// or an address.
type LeftOutWay struct {
	Way    string `json:"way"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// shareWayLabel is the short name a link carries in its #fragment, which
// is what the other app shows in its list.
func shareWayLabel(way string) string {
	switch way {
	case ShareWayReality:
		return "REALITY"
	case ShareWayHysteria2:
		return "Hysteria 2"
	case ShareWayShadowsocks:
		return "Shadowsocks"
	case ShareWayCDN:
		return "WebSocket TLS · Cloudflare"
	}
	return way
}

// ShareLinksForRecipient renders the share links for one person from the
// same signed .sbp and per-person credentials the per-person pack is
// minted from (RewriteProfilesForRecipient). labelPrefix, when set, is
// put before each way's name in the link's label ("<prefix> · REALITY").
//
// It returns the links, the ways left out (each with a reason code), and
// an error only when the pack cannot be read or a rendered link
// disagrees with what the pack was signed for (ErrStaleSignedPack). No
// links at all is not an error: the caller says so.
func ShareLinksForRecipient(sbp []byte, p ClientConnParams, labelPrefix string) ([]ShareLink, []LeftOutWay, error) {
	b, err := bundle.ParseSBP(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		return nil, nil, fmt.Errorf("share links: parse sbp: %w", err)
	}
	label := func(way string) string {
		if s := strings.TrimSpace(labelPrefix); s != "" {
			return s + " · " + shareWayLabel(way)
		}
		return shareWayLabel(way)
	}

	links := []ShareLink{}
	left := []LeftOutWay{}
	done := map[string]bool{}
	leave := func(way, reason, detail string) {
		if done[way] {
			return
		}
		done[way] = true
		left = append(left, LeftOutWay{Way: way, Reason: reason, Detail: detail})
	}
	add := func(way, link string) {
		done[way] = true
		links = append(links, ShareLink{Way: way, Label: label(way), Link: link})
	}

	for _, route := range b.Manifest.Routes {
		family := route.TransportFamily
		if bundle.HasCDNEndpoint(route.FamilySpecificConfig) {
			if done[ShareWayCDN] {
				continue
			}
			link, reason, detail := cdnShareLink(route, p, label(ShareWayCDN))
			if reason != "" {
				leave(ShareWayCDN, reason, detail)
				continue
			}
			add(ShareWayCDN, link)
			continue
		}
		if done[family] {
			continue
		}
		switch family {
		case ShareWayReality, ShareWayShadowsocks:
		case ShareWayHysteria2, string(bundle.TransportWebSocketTLS), string(bundle.TransportNaive), "tuic", "anytls":
			leave(family, LeftOutNeedsInsecure,
				"this way uses the relay's own certificate, which a share link cannot pin; "+
					"another app could use it only with certificate checks turned off")
			continue
		default:
			leave(family, LeftOutNoLinkFormat, "there is no share-link format for this way")
			continue
		}

		port := portFromProfile(b.Profiles[route.ConfigPath])
		if port == 0 {
			port = defaultClientPort(family)
		}
		ob, err := ClientOutboundForFamily(family, port, p)
		if err != nil {
			leave(family, LeftOutMissingMaterial,
				"this person's key for this way is not known here")
			continue
		}
		ep, epErr := bundle.ParseEndpoint(route.FamilySpecificConfig)
		if errors.Is(epErr, bundle.ErrNoEndpoint) {
			leave(family, LeftOutNotSigned, "the signed pack carries no endpoint for this way")
			continue
		}
		if epErr != nil {
			return nil, nil, fmt.Errorf("share links: route %s: %w", route.ID, epErr)
		}
		if err := bundle.CheckOutbound(family, ep, ob); err != nil {
			return nil, nil, fmt.Errorf("share links: route %s (%s): %w (%v)",
				route.ID, family, ErrStaleSignedPack, err)
		}

		switch family {
		case ShareWayReality:
			add(family, realityShareLink(ep, p, label(family)))
		case ShareWayShadowsocks:
			add(family, ssShareLink(ep, p, label(family)))
		}
	}
	return links, left, nil
}

// hostPort joins a host and port, bracketing an IPv6 literal.
func hostPort(host string, port int) string {
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}

func fragment(label string) string {
	return "#" + (&url.URL{Fragment: label}).EscapedFragment()
}

// realityShareLink: vless://uuid@host:port?…security=reality&pbk=&sid=&sni=&fp=chrome&flow=…
// The server, port, cover host and key are the SIGNED endpoint's, which
// CheckOutbound has just held the outbound to.
func realityShareLink(ep *bundle.Endpoint, p ClientConnParams, label string) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", "xtls-rprx-vision")
	q.Set("security", "reality")
	q.Set("sni", ep.ServerName)
	q.Set("fp", "chrome")
	q.Set("pbk", ep.RealityPublicKey)
	q.Set("sid", p.RealityShortID)
	q.Set("type", "tcp")
	return "vless://" + url.PathEscape(p.VLESSUUID) + "@" + hostPort(ep.Server, ep.Port) +
		"?" + q.Encode() + fragment(label)
}

// hy2ShareLink: hysteria2://password@host:port/?sni=&pinSHA256=#label —
// never insecure=1. pinSHA256 is Hysteria's pin (SHA-256 of the whole
// DER certificate, hex), computed from the relay's certificate after its
// key is checked against the SIGNED SPKI pin; without that certificate
// there is no pin and so no link.
func hy2ShareLink(ep *bundle.Endpoint, p ClientConnParams, label string) (string, string, string) {
	certPin, ok := hy2CertPin(p.TLSCertPEM, ep.TLSSPKISHA256)
	if !ok {
		return "", LeftOutMissingMaterial,
			"the relay's certificate is not kept here, or does not carry the signed key, so the link could not be pinned"
	}
	q := url.Values{}
	if ep.ServerName != "" {
		q.Set("sni", ep.ServerName)
	}
	q.Set("pinSHA256", certPin)
	return "hysteria2://" + url.PathEscape(p.Hy2Password) + "@" + hostPort(ep.Server, ep.Port) +
		"/?" + q.Encode() + fragment(label), "", ""
}

// hy2CertPin returns the hex SHA-256 of the one certificate in certPEM,
// only when that certificate's key is the one the pack signed.
func hy2CertPin(certPEM, signedSPKI string) (string, bool) {
	if strings.TrimSpace(certPEM) == "" || signedSPKI == "" {
		return "", false
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", false
	}
	spki, err := bundle.SPKIPinFromCertPEM(certPEM)
	if err != nil || spki != signedSPKI {
		return "", false
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), true
}

// ssShareLink: SIP002 ss://method:password@host:port#label. A 2022
// method's userinfo is percent-encoded plaintext, never base64 (SIP022);
// the password is the relay's "<iPSK>:<uPSK>", whose ':' '+' '/' '=' are
// all escaped.
func ssShareLink(ep *bundle.Endpoint, p ClientConnParams, label string) string {
	return "ss://" + url.QueryEscape(p.SSMethod) + ":" + url.QueryEscape(p.SSPassword) +
		"@" + hostPort(ep.Server, ep.Port) + fragment(label)
}

// cdnShareLink: vless over WebSocket TLS to a Cloudflare edge address,
// TLS to the signed name, checked by the public CA chain. The outbound
// Daal's own file would carry is rendered first (CDNClientOutbound holds
// it to the signed commitment), so the link names the same edge, port,
// name and path.
func cdnShareLink(route bundle.RouteManifestEntry, p ClientConnParams, label string) (string, string, string) {
	ep, err := bundle.ParseCDNEndpoint(route.TransportFamily, route.FamilySpecificConfig)
	if err != nil {
		return "", LeftOutNotSigned, "the signed way in through Cloudflare is not one this build can read"
	}
	if !ep.PlainFallback {
		return "", LeftOutShowsCDNName,
			"a link cannot carry the hidden name (ECH), and this relay does not allow its Cloudflare name to show"
	}
	if _, err := CDNClientOutbound(ep, p); err != nil {
		return "", LeftOutMissingMaterial, "the way in through Cloudflare is not fully known here"
	}
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "tls")
	q.Set("sni", ep.ServerName)
	q.Set("fp", "chrome")
	q.Set("type", "ws")
	q.Set("host", ep.ServerName)
	q.Set("path", strings.TrimSpace(p.CDNWSPath))
	return "vless://" + url.PathEscape(p.VLESSUUID) + "@" + hostPort(ep.FirstEdgeAddress(), ep.Port) +
		"?" + q.Encode() + fragment(label), "", ""
}
