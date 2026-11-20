package uri

// AmneziaWG handling lives entirely in wireguard.go: a wg-quick .conf is
// recognized as AmneziaWG iff any 1.x (Jc/Jmin/Jmax/S1/S2/H1..H4) or 2.0
// (S3/S4/I1..I5/J1..J3/ITIME) field is present in the [Interface]
// section, and amneziaWireCompatible decides between a plain-WireGuard
// downgrade and an unsupported "amneziawg" route. This file is a
// placeholder that keeps the package layout matching the spec.
