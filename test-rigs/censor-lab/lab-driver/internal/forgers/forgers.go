// Package forgers will host small Go helpers that run in the censor
// namespace during live runs (DNS forgery, SNI/IP RST injection, first-bytes
// whitelist, fingerprint dropping, stateful reassembly variant). Phase 0C
// scopes the public surface; concrete implementations land per scenario as
// they are exercised on real Linux hosts. The replay path does not depend
// on this package.
package forgers

// Kind identifies a forger implementation.
type Kind string

const (
	KindDNSForge          Kind = "dns_forge"
	KindTLSSNIRst         Kind = "tls_sni_rst"
	KindIPRst             Kind = "ip_rst"
	KindUDPBlackhole      Kind = "udp_blackhole"
	KindUDPSignatureDrop  Kind = "udp_signature_drop"
	KindProtocolWhitelist Kind = "protocol_whitelist"
	KindStatefulReassem   Kind = "stateful_reassembly"
	KindTLSinTLSBurst     Kind = "tls_in_tls_burst"
	KindQUICSNIDrop       Kind = "quic_sni_drop"
)
