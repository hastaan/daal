# \*\*Technical Report on Vital Keys in the Design and Implementation of Smart and Sustainable Internet Censorship: Proposed Model for Controlled Phased Unblocking, Identification of Technical Loopholes, and Solutions for Closing Them\*\*

# 

# \*\*Prepared by:\*\* Dr. Rasoul Jalili's Research Team - Amn Afzar Gostar Sharif Technical Group

# \*\*Date:\*\* September 2025 (Shahrivar 1404)

# \*\*Version:\*\* 2.2

# 

# \*\*Abstract:\*\*

# Managing external internet traffic flow requires a delicate balance between facilitating legitimate access and preserving cyber sovereignty. The only sustainable solution is the implementation of a phased and completely controlled unblocking. This report proposes a four-stage unblocking model, where each stage has a specific technical and operational objective. Technical loopholes in each stage are blocked with dedicated signatures, functional restrictions, and the blocking of unnecessary protocols. Key recommendations include restricting file sharing in domestic messengers, prohibiting anonymous file uploads in Iranian uploaders, fully blocking outbound IPv6, UDP, and ICMP, prioritizing the unblocking of vital sites for mobile operators first, and mandating 100% of Iranian sites and services to use the National Content Delivery Network (CDN). Based on simulations, the implementation of this model will reduce unauthorized traffic leakage by up to 97%.

# 

# \*\*Introduction:\*\*

# The operational experience of the years 2022 to 2025 (1401 to 1403) has shown that sudden unblocking without prior technical analysis quickly becomes the primary factor in activating layer 4 and 5 circumvention tools. The research team, with access to raw data from the National Information Network (NIN), has identified this recurring pattern. The current proposed model is a four-stage gradual unblocking, where the exact goal is declared at each stage, technical loopholes are anticipated and corresponding signatures are prepared, and a real-time monitoring and active rollback mechanism is in place.

# 

# \*\*Stage One: Reducing restrictions on national apps and services:\*\* This stage is implemented with the aim of improving the user experience quality of domestic services without creating any direct route to the external internet. The focus is exclusively on traffic within the National Information Network. In this stage, there is a possibility of hiding tunneling traffic within the permitted streams of messengers and banking services. To counter this loophole, applying 3rd generation DPI with behavioral and payload-based signatures is essential. Also, file transmission in domestic messengers must be limited to a maximum of 5 megabytes per session, server-side malware scanning must be mandatory, and executable formats must be completely banned. Real-time monitoring of traffic entropy and packet size distribution must also be performed continuously.

# 

# \*\*Stage Two: Whitelisting vital sites:\*\* This stage is designed to prevent disruptions to legitimate businesses and official communications. Here, the unblocking of DNS resolvers and AnyCast of CDNs... \[continued from next page] ...can enable domain fronting and VPN traffic routing. The team's solution is granular whitelisting as a combination of FQDN, IP address prefix, and port. The unblocking of vital sites must initially be done only on mobile operator networks to allow for more precise monitoring and, if necessary, the identification of the violator within the first 48 hours. After confirming no leakage, it should be expanded to fixed-line operators. Simultaneously, all resolvers must be forced to the National DNS, and third-party DoH/DoT must be blocked.

# 

# \*\*Stage Three: Unblocking Artificial Intelligence Service Platforms:\*\* This stage is implemented with the aim of providing controlled access for knowledge-based companies and authenticated users to AI models. Actual experience in July 2025 (Tir 1404) showed that opening access to ChatGPT simultaneously activated the Cloudflare WARP service, because both use the same Anycast. Additionally, traffic routing through the Azerbaijan network to bypass sanctions played a role in this problem. Within 72 hours, the Amn Afzar Gostar Sharif technical team designed a dedicated WARP signature based on the initial handshake pattern, specific sequence numbers, and packet entropy, which now has a 100% blocking capability without disrupting ChatGPT. Therefore, unblocking in this stage should only be done after the preparation of dedicated signatures and laboratory testing, and access should be limited to users with two-factor authentication and a static IP address.

# 

# \*\*Stage Four: Gradual Unblocking of Network Protocols:\*\* This stage is solely anticipated for resolving network troubleshooting issues and supporting modern protocols in controlled operational cases. In this stage, ICMP creates the possibility of tunneling, and IPv6 enables 6to4 and Teredo tunneling. The definitive solution is the complete and permanent blocking of outbound IPv6, UDP, and ICMP (except in exceptional and strictly rate-limited cases). A stateful IPv6 firewall with full inspection of extension headers must be implemented, and a rate-limiting of ten packets per second combined with machine learning-based anomaly detection must be applied. Likewise, the number of outbound ICMP packets per session should not exceed a specific number (e.g., 3).

# 

# \*\*Mandatory Policy Recommendations:\*\*

# \* Prohibiting file uploads without logging in across all Iranian uploaders, with mandatory two-factor authentication (SMS), is essential.

# \* Additionally, all Iranian sites and services must be 100% placed behind the National Content Delivery Network (CDN) so that from outside the country, only the IP addresses of the National CDN are visible and accessible.

# \* Foreign Content Delivery Networks (CDNs) are considered the primary and known agents of unauthorized access; because a vast number of foreign sites—including some essential services—are located behind these infrastructures. Based on the operational experiences of the research team, in the first stage of unblocking, granting any access to these CDNs must be completely avoided to prevent the creation of widespread loopholes. In cases of compulsion and necessity in the second stage, unblocking must be extremely limited and implemented with precise whitelisting based on specific ports and IP prefixes, combined with full DPI... \[continued from next page] ...and signature-based inspection on all traffic flows of that CDN, along with the immediate blocking of any simulated VPN connections such as QUIC, WireGuard, or WARP, must be performed so that legitimate access is preserved while bypass routes remain blocked.

# 

# \*\*Executive Procedure in Crisis Mode:\*\*

# In crisis situations (such as widespread disruptions or severe external pressure), all stages of unblocking are put into complete suspension. Immediate and unconditional blocking of IPv6, UDP, and ICMP, and other unnecessary protocols is applied; file transmission in all domestic messengers and uploaders is halted (or applied with severe restrictions and minimum volume). To prevent the spread of unauthorized services, access to vital sites is minimized (only email and basic search) and, in the event of no pressure on domestic platforms, is stopped. DPI monitoring is upgraded to maximum and real-time status, and any suspicious traffic is automatically dropped.

# 

# \*\*Executive Procedure in Exiting Crisis Mode:\*\*

# Upon returning to normal conditions, the unblocking is resumed step-by-step, strictly following the four-stage sequence. First, stage one (national services) is activated and restrictions are reduced, and after 72 hours of monitoring and confirming no leakage, stage two begins. Updated signatures and protocols are re-tested and applied. File sending restrictions return to normal (5 megabytes with scanning), and the National Content Delivery Network is maintained as the primary protection layer. This process allows research teams to identify and disable remaining methods of unauthorized communication and makes identifying the user easier.

# 

# The four-stage controlled unblocking model is the only scientific and practical approach to maintain the balance between legitimate access and national security. Its successful execution requires close cooperation between the Telecommunication Infrastructure Company and the Amn Afzar Gostar Sharif technical team. I am prepared to provide a comprehensive technical report, signature files, a full simulation report, and a detailed implementation plan at the border gateway level.

# 

# 

# Three GitHub tools, three evasion philosophies, one failing filternet

**Iran's filtering apparatus in 2025–2026 has collapsed into a hybrid of stateless SNI-DPI, bogon DNS injection, protocol whitelisting at the TCI national edge, and tiered-access policy — and three GitHub projects exemplify the three cleanest technical responses to this environment.** `patterniha/MITM-DomainFronting` is a client-side TLS MITM recipe bolted onto Xray-core that exploits CDN same-origin fronting; `masterking32/MasterHttpRelayVPN` is a Python HTTP-request relay that hides traffic inside Google Apps Script fetches; `PechenyeRU/FakeSNI` is a Go Linux port of an Iranian out-of-window TLS desync trick that poisons the DPI's SNI extractor with a stale fake ClientHello. All three are serverless or quasi-serverless, each sacrifices something different (cert pinning, TLS fingerprint, protocol coverage), and each breaks at a specific DPI capability upgrade that Iran has not yet universally deployed. Below, the censorship backdrop, then one dense section per tool, then a comparative verdict.

## How Iran's filternet actually works

**Architecture.** The Telecommunication Infrastructure Company (TIC), fronted by TCI's AS58224, funnels essentially all international egress through a small number of physical chokepoints (the "LCT building" repeatedly named in Filterwatch reporting). Downstream ISPs — MCI/AS197207, IranCell/AS44244, Shatel, HiWeb — inherit TCI's policy. IR-IX peers the domestic fabric so traffic to Aparat, Snapp, Digikala, Bank Mellat, and dolat.ir never touches the international edge. This separability is what enables **"closed-loop" blackouts**: the Shoma/NIN domestic mesh keeps routing while the international edge drops anything outside a narrow whitelist. Unlike the GFW, Iran's filter is **in-path**, so it drops rather than merely injects — though SNI-based blocking still uses a TCP RST toward the client.

**What the DPI actually does.** Bock et al.'s canonical FOCI 2020 analysis, corroborated by IRBlock (USENIX Security 2025) and Niere et al. (PoPETs FOCI 2025), establishes two key properties that every tool in this report exploits: the Iranian DPI **inspects only the first two data-carrying packets** of a flow and **does not perform full TCP stream reassembly**. It parses the TLS ClientHello's `server\_name` extension; on blacklist hit, it emits an RST immediately after the ClientHello. In "heavy" mode, it enforces a **protocol whitelist** requiring flows to begin with DNS/HTTP/TLS signatures (HTTP verbs `GET|POST|HEAD|CONNECT|OPTIONS|DELETE|PUT` in the first ≥8 bytes, UDP-DNS wire format, TLS record-type `0x16`) and silently drops everything else — this is what killed OpenVPN, WireGuard, IKEv2, Tor obfs4 (since roughly 2023), Hysteria, and most QUIC traffic during the June 2025 Twelve-Day War and the January 2026 blackout.

**DNS manipulation and ECH suppression.** Iranian resolvers (and inline forgers on UDP/53) return **bogon RFC1918 addresses — 10.10.34.34, 10.10.34.35, 10.10.34.36** — for blocked domains, with abnormally low TTLs. Since September 2022, DoH endpoint domains themselves (`cloudflare-dns.com`, `doh.opendns.com`) are resolved to bogons, and the TLS handshake to 1.1.1.1 is SNI-blocked. Niere et al. established that this is precisely **how Iran kills ECH**: without a resolvable HTTPS RR, clients cannot fetch the ECHConfig, so the `encrypted\_client\_hello` extension never materializes. Iran doesn't need to block ECH in-band (as Russia's TSPU does) when it kills the bootstrap.

**Protocol status and IP-range pressure.** OpenVPN/WireGuard/IKEv2 are first-packet-fingerprint dead. Shadowsocks with stream ciphers is fingerprinted via entropy analysis. VMess-WS is dead. **VLESS + XTLS-Vision + REALITY** was the de facto surviving protocol through 2024 but is now flagged by traffic-volume heuristics plus suspected reverse-DNS mapping of cover SNIs (XTLS #3269), with IPs on MCI burning in 2–7 days. DigitalOcean and OVH ranges are blanket-blocked on VPN detection; Hetzner is graylisted; **Cloudflare, Azure, GCP, and Akamai ranges are never wholesale blocked** due to collateral damage — filtering is exclusively SNI-based on those. Azure Front Door killed classic domain fronting globally on 8 January 2024 by enforcing SNI==Host; Google and AWS killed theirs in 2018; **Fastly, Akamai, and some Cloudflare configurations still permit SNI≠Host** in 2025–26, which is the precondition for the first tool below.

**Recent blackouts.** The **June 2025 "stealth blackout"** during the Twelve-Day War dropped international traffic \~90–97% while preserving BGP announcements — the full protocol-whitelist posture. The **8 January 2026 blackout** was preceded by a –98.5% IPv6 announcement collapse and an HTTP/3 share drop from 40% to <5% (indicating UDP/QUIC pre-tightening). At the time of writing — 22 April 2026 — international connectivity is at roughly 1% of baseline on parts of the network, Starlink possession is a capital offense, and "Internet Pro" tiered access is being sold to vetted businesses. **This is the environment these three tools operate in.**

## Project 1 — patterniha/MITM-DomainFronting: local TLS decryption for CDN re-fronting

**What it is.** A 116-star, single-commit repository containing only a README and LICENSE. There is no committed source code. The repository is a **usage recipe** on top of Xray-core (Go), whose author (`patterniha`) co-developed the upstream "fromMitm" freedom-outbound code path with `@RPRX` in Xray v25.3.x. The user-facing deliverable is a **SOCKS/HTTP proxy on 127.0.0.1** consumed by v2rayN on Windows or v2rayNG with `hev-socks5-tunnel` on Android. **No remote server.** The sister repo is literally named `Serverless-for-Iran`.

**Protocol-level flow.** Xray runs a `dokodemo-door` inbound configured with `streamSettings.security="tls"` and a certificate with `usage: "issue"`. When a browser opens a TLS connection destined for — say — `www.instagram.com`, Xray terminates the handshake using a **per-domain leaf certificate minted on the fly from a locally-generated root CA** (`mycert.crt` + `mycert.key`, produced by `xray tls cert -ca`). Because `followRedirect: true` is set, dokodemo extracts the real destination `host:port` from the sniffed SNI rather than the local loopback address. The user must install the local CA into the system trust store (on Android: *Settings → Security → CA certificate*; on Firefox: the hidden `security.enterprise\_roots.enabled` toggle). Once decrypted, Xray hands the plaintext HTTP/HTTPS stream to a `freedom` outbound, which **re-encrypts with a rewritten SNI**: the outer ClientHello carries a fronting domain (e.g., a TCI-whitelisted Iranian host on the same CDN) while the HTTP/1.1 `Host` header or HTTP/2 `:authority` pseudo-header remains the real target. This is classical domain fronting.

Two implementation details matter. First, **uTLS Chrome fingerprinting** (`fingerprint: "chrome"` or randomized variants) produces a ClientHello byte-identical to Chrome — cipher order, GREASE, X25519+secp256r1 key-shares, ALPN `h2, http/1.1` — defeating JA3/JA4 classification. Second, the special string **`"fromMitm"`** in `serverName`, `verifyPeerCertInNames`, and `alpn` fields propagates values from the decrypted browser session into the outer handshake, so ALPN is preserved end-to-end and HTTP/2 does not silently degrade to HTTP/1.1; Xray explicitly errors "unexpected Negotiated Protocol" if the CDN downgrades. DNS resolution of both fronting and real domains happens through Xray's built-in DoH (`h2c://` plaintext-HTTP/2 DoH) tunneled through the same fronted outbound, with patterniha's `expectedIPs/priorIPs/unexpectedIPs` logic (Xray PR #4611) picking per-CDN IPs.

**Infrastructure.** No VPS, no account, no token. Outbound TCP/443 to Cloudflare, Fastly, Google CDN, Discord CDN, Microsoft CDN, Akamai edges. The companion `Serverless-for-Iran` config adds **chained TLS fragmentation** (`super-fragment`, `chain1-fragment`, `chain2-fragment` splitting ClientHellos into 6-byte and 1-byte pieces with 1–2 ms intervals) plus UDP noise injection to defeat statistical throttling. Iranian CDNs (ArvanCloud, Derak) are deliberately never used as fronts — they cooperate with TCI and wouldn't help reach foreign origins.

**Failure modes.** The **cert-pinning cliff** is the biggest user-facing limitation: Telegram, banking apps, Signal — anything with pinning — rejects the local CA, so MITM-DomainFronting effectively works only for browsers. Upstream, the scheme requires that the chosen CDN still honors **SNI≠Host** routing, a property Cloudflare, Fastly, and Akamai have partially killed since 2018–2022 (Google, AWS, and Azure Front Door killed it entirely). Where a CDN now enforces SNI==Host or returns a default cert mismatch, Xray's `verifyPeerCertInNames` check catches it cleanly, but the tunnel simply won't establish. Wholesale IP-block of a CDN (as with Telegram's entire IP space) kills the approach. The TLS fingerprint itself is solid — Chrome uTLS matches a real Chrome — but any CDN cooperation with TCI (ArvanCloud-style) or any future ECH deployment would actually **break** this scheme, because ECH encrypts the outer SNI and the whole front/target split assumption collapses.

**Implementation.** Go, via Xray-core; key libraries are `refraction-networking/utls`, Go `crypto/tls`, patched `quic-go` v0.48.2, gVisor for TUN, `hev-socks5-tunnel` for Android. Config is a JSONC with a `dokodemo-door` inbound tagged `tls-decrypt`, a `freedom` outbound with `tlsSettings.serverName` set to the front and `verifyPeerCertInNames:\["fromMitm"]` pinning the inner cert, plus routing that sends TLS-port traffic through the decrypt stage. The canonical example lives at `XTLS/Xray-examples/MITM-Domain-Fronting/config.jsonc`.

## Project 2 — masterking32/MasterHttpRelayVPN: Google Apps Script as free relay

**What it is.** Despite the name, **it is not a VPN and tunnels no Layer-3 packets.** It is a Python HTTP(S) forward proxy (primary language 96.4% Python, 3.6% JavaScript for the relay) on the `python\_testing` branch that does **local TLS MITM on the browser** and forwards each decrypted HTTP request as a JSON envelope to a **Google Apps Script web app the user deploys in their own Google account**. Author Amin Mahmoudi (`@masterking32`, Iran-based), special thanks to `@abolix`. Star count varied 16 → 646 across fetch attempts, indicating rapid viral growth on Iranian Telegram channels during a 2026 filtering wave.

**Protocol-level flow.** The browser connects to `127.0.0.1:8085` (HTTP proxy) or `:1080` (SOCKS5). For `CONNECT host:443`, the proxy **does not tunnel transparently** — it replies `200 Connection established`, then MITMs the TLS with a leaf cert for `host` minted from a locally-generated root CA (`ca/ca.crt` + `ca/ca.key`, managed by `mitm.py`), which the user must install into the OS trust store via `main.py --install-cert`. After decryption, `domain\_fronter.py` serializes the request as JSON — `{k: AUTH\_KEY, m: METHOD, u: FULL\_URL, h: {headerMap}, b: base64(body), ct: content-type, r: followRedirects}` — and POSTs it **over HTTPS to `216.239.38.120` (a Google anycast IP) with SNI=`www.google.com` but `Host: script.googleusercontent.com`**. This works because Google's GFE (Google Front End) terminates both `www.google.com` and `script.googleusercontent.com` on the same edge and routes by Host header — a same-frontend quirk that outlived Google's public 2018 shutdown of general-purpose domain fronting. An optional `h2\_transport.py` multiplexes many concurrent streams over one fronted TLS session.

The Apps Script (`Code.gs`, 141 lines) runs in Google's V8 runtime, authenticates via a static shared `AUTH\_KEY`, strips hop-by-hop headers, and executes `UrlFetchApp.fetch(url, opts)` — returning `{s: statusCode, h: responseHeaders, b: base64(body)}`. A batch path uses `UrlFetchApp.fetchAll(...)` to fire multiple requests in parallel inside Google's NoC. `doGet` returns a bland "Welcome" HTML decoy. Each HTTP transaction is an independent RPC — **there is no persistent socket tunnel** through Apps Script. For bulk Google-owned hosts where Apps Script's \~50 MB/fetch body cap and \~20k/day consumer quota would be prohibitive (YouTube chunks, googlevideo, gstatic, fonts.googleapis.com), a secondary **"SNI-rewrite tunnel"** opens a raw TCP-over-TLS connection directly to the Google anycast IP with SNI=`www.google.com` and inner `Host: <real target>` — **the same trick as Project 1, just without the MITM re-encryption step**.

**Infrastructure.** No VPS. A free Google account suffices (Apps Script deployment: `Execute as: Me`, `Who has access: Anyone`). Outbound 443/tcp to Google only. No Docker, no systemd — bare `python main.py`. Key Python deps: `cryptography` (for on-the-fly leaf cert issuance), `h2` (HTTP/2 multiplexing), stdlib `ssl` and `socket`. The README even offers a PyPI mirror (`mirror-pypi.runflare.com`) for users who cannot reach the real PyPI from Iran. Multi-deployment load-balancing via `script\_ids: \[ID1, ID2, ID3]` spreads load across several Google accounts to stretch the daily quota.

**Failure modes.** The political dependency is **total: Iran not blocking Google**. Gmail, Android, and Play Services collateral has kept Google off the blocklist, but there is no technical reason it couldn't change. The first DPI capability that would kill this tool quietly is **JA3/JA4 classification of traffic to AS15169** — Python's stdlib `ssl` produces a distinctive non-Chrome ClientHello, and at scale from Iranian home ISPs, "sustained POSTs to `216.239.38.120` with Python-shaped TLS" is a trivially classifiable signature. There is **no uTLS mimicry, no padding, no cover traffic, no constant-bitrate shaping**; the asymmetric upload pattern (many POSTs up, JSON responses down) is behaviorally unlike normal browsing. The `Google-Apps-Script` User-Agent forced by `UrlFetchApp` means sites with bot detection (search, CAPTCHAs) serve degraded content. **SOCKS5 breaks Telegram** because SOCKS sends already-resolved IPs and the local proxy can't intercept raw MTProto ciphertext — the README forces Telegram users to the HTTP proxy mode. On the plus side, **burn-and-replace is near-free**: a new Google account + fresh deployment takes \~60 seconds. Apps Script quota exhaustion resets at midnight Pacific (10:30 AM IRST), which the README helpfully notes.

**Implementation notes.** `main.py` (entry, CLI), `proxy\_server.py` (HTTP/SOCKS5 listeners), `mitm.py` (CA + leaf cert minting), `domain\_fronter.py` (Apps Script client), `h2\_transport.py` (optional h2 multiplexing), `ws.py` (WebSocket upgrade), `Code.gs` (relay). Auth is a **shared static secret** with no HMAC, no nonce, no replay protection. License MIT. A Rust port by `therealaleph` exists for distribution convenience but inherits the same fingerprint weakness. A sibling project `MasterDnsVPN` is a true DNS-tunneling L4 VPN (Go, requires user-delegated NS) — unrelated but relevant for comparative context.

## Project 3 — PechenyeRU/FakeSNI: out-of-window stale ClientHello injection

**What it is.** A very new (first commit April 2026, `v0.1.0` on 13 April 2026), Linux-only, Go 1.22+, single-destination TCP pre-proxy. The **only committer visible is `@claude`** (Anthropic's Claude model identity on GitHub), and the README explicitly describes the project as "a fast, clean Go port of [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) for Linux." Despite the Russian-flavored org name (*пече́нье* = "cookie"), **the technique and default values (`CONNECT\_IP=188.114.98.0`, a Cloudflare edge; `FAKE\_SNI=auth.vercel.com`) are straight from the Iranian anti-filter ecosystem** (siblings: `aleskxyz/SNI-Spoofing-Go`, `therealaleph/sni-spoofing-rust`, `SamNet-dev/snix`, `Rainman69/SNISPF`). It is a **pre-proxy for an upstream Xray/VLESS client**, not a system-wide bypass like GoodbyeDPI or zapret.

**Protocol-level technique: the stale pre-ISN segment.** This is the interesting part. For every flow toward the configured `CONNECT\_IP:CONNECT\_PORT`:

1. User-space `proxy.go` accepts the local client and registers the intended 4-tuple.
2. The kernel completes the TCP 3-way handshake with the real CDN (SYN, SYN-ACK, ACK). An `iptables -j NFQUEUE` rule routes these packets through `injector.go` via `github.com/florianl/go-nfqueue`.
3. Immediately after observing the final ACK leaving the host, `injector.go` uses a raw socket (`AF\_INET/SOCK\_RAW/IPPROTO\_TCP`) plus `gopacket` to forge a TCP segment whose payload is a **minimal TLS 1.2 ClientHello carrying `server\_name = auth.vercel.com`** (built by `clienthello.go`).
4. The critical trick: the forged segment uses `seq = syn\_seq + 1 - len(payload)`, placing its bytes **before the negotiated ISN+1 — to the left of the server's receive window**.
5. The on-path DPI, parsing first-packet TLS, extracts `auth.vercel.com` from the stale segment, classifies the flow as benign Vercel traffic, and whitelists the 5-tuple.
6. The real server discards the stale segment as out-of-window and emits a **duplicate ACK** (RFC 793/5681). `proxy.go` waits on that dup-ACK, then flushes the real ClientHello (with the real target SNI). The DPI has already committed its verdict and typically does not re-examine subsequent records.

**Two critical engineering details.** The tool **must write `1` to `/proc/sys/net/netfilter/nf\_conntrack\_tcp\_be\_liberal`** or Linux's own conntrack would drop the stale segment returning through the socket. This is restored on graceful shutdown but is a **system-wide side effect** — a real operational concern for shared hosts. And unlike GoodbyeDPI or zapret, **there is no TTL manipulation and no SNI fragmentation**: the real server's discard of the stale segment is purely sequence-number-based, not TTL-exhaustion-based. The real ClientHello is sent intact.

**Capability surface.** IPv4 only (no `ip6tables` rules installed). TCP only — **no QUIC/UDP 443, no HTTP/80, no DNS hardening, no DoH, no ECH/ESNI**. Single hard-coded destination per run (no strategy library, no multi-target, no allow-list). The iptables rules are narrow:

```
iptables -I OUTPUT -p tcp -s <iface> -d <CONNECT\_IP> --dport <CONNECT\_PORT> -j NFQUEUE --queue-num 100 --queue-bypass
iptables -I INPUT  -p tcp -s <CONNECT\_IP> --sport <CONNECT\_PORT> -d <iface> -j NFQUEUE --queue-num 100 --queue-bypass
```

`--queue-bypass` ensures that if the userspace process dies, packets are accepted rather than dropped — smart defensive choice for a tool running as root with `CAP\_NET\_ADMIN + CAP\_NET\_RAW`.

**Failure modes.** The technique works against **stateless / first-packet-only DPI** — which is the dominant Iranian steady-state filter and Russia's TSPU in many provinces — and fails against any DPI that performs **per-flow TCP sequence-window tracking and reassembly**. A Zeek- or Suricata-shaped IDS would see the pre-ISN bytes and either discard them or correctly reassemble only the real ClientHello, extracting the real SNI and RSTing. More worryingly, the injected pattern (one extra segment with pre-ISN sequence numbering appearing \~1 ms after the 3WHS) is **deterministically unique to this class of tools** — a single DPI signature upgrade fingerprinting "stale-seq injection immediately after ACK" would kill every flow produced by FakeSNI and its siblings at once. IP-layer blocking of the Cloudflare edge (or whatever `CONNECT\_IP` is chosen) bypasses the SNI trick entirely, and Iran has been progressively graylisting specific Cloudflare IPs associated with known configs — hence the parallel ecosystem of "clean CF IP" scanners (CFScanner, etc.) that `FakeSNI` itself doesn't include. Any corporate NAT, CGNAT, or stateful middlebox between host and DPI that tracks seq windows silently drops the stale segment and the trick dies. No ECH means **the real SNI is still sent in plaintext** in the legitimate ClientHello; the "fake" is misdirection of a stateless parser, not cryptographic SNI hiding.

**Implementation.** Go 100%, no cgo, no Makefile, single `go build`. Dependencies: `github.com/florianl/go-nfqueue`, `github.com/google/gopacket`, `golang.org/x/sys`. Files: `main.go`, `config.go`, `proxy.go`, `injector.go`, `clienthello.go`, `system.go`. Config is the canonical Iranian-family JSON schema:

```json
{
  "LISTEN\_HOST": "0.0.0.0", "LISTEN\_PORT": 40443,
  "CONNECT\_IP": "188.114.98.0", "CONNECT\_PORT": 443,
  "FAKE\_SNI": "auth.vercel.com",
  "QUEUE\_NUM": 100, "HANDSHAKE\_TIMEOUT\_MS": 2000
}
```

No LICENSE file in the repo (likely GPL-inheriting from the upstream Iranian work but unadvertised). 2 commits, 1 star, 0 forks on the authoritative page render. This is a thin LLM-authored artifact of an existing Iranian technique, not independent research.

## Comparative verdict

The three tools attack three different layers of the Iranian filter and therefore have orthogonal failure conditions:

|Dimension|MITM-DomainFronting|MasterHttpRelayVPN|FakeSNI|
|-|-|-|-|
|**Attack layer**|Application (CDN Host routing)|Application (Google Apps Script as relay)|Transport (TCP seq desync)|
|**Infrastructure cost**|Zero|Free Google account|Upstream CDN IP (shared)|
|**TLS fingerprint**|uTLS Chrome (strong)|Python stdlib (weak)|N/A — forged segment is TLS-shaped bytes only; real hop uses caller's stack|
|**Cert pinning friendly**|No (browsers only)|No (browsers only)|Yes (no MITM)|
|**Protocol coverage**|Any HTTP/HTTPS|HTTP/HTTPS only, no raw TCP|Any TLS flow to configured IP|
|**Kills on**|CDN enforcing SNI==Host, IP-block of edge, cert pinning|Iran blocking Google, JA3 classification on AS15169, Apps Script suspension|Stateful reassembly DPI, IP-block of edge, stale-seq pattern signature|
|**Burn cost**|N/A (no assets)|\~60s (new Google account)|N/A (shared CF IPs)|
|**IPv6 / QUIC**|via Xray|No|No|

**The strongest technically.** MITM-DomainFronting dominates on TLS fingerprint fidelity (Chrome uTLS + GREASE + genuine ALPN) and on the breadth of the Xray ecosystem (TCP fragmentation, UDP noise, DoH with Host routing). Its Achilles' heel is **cert pinning** — no mobile app with pinning can use it — and the **shrinking set of CDNs that still honor SNI≠Host**. Every year since 2018 has narrowed this surface; Azure Front Door's January 2024 shutoff was the most recent major loss.

**The most operationally clever.** MasterHttpRelayVPN converts a Google policy constraint ("we can't afford to block Google") into free, burnable relay capacity. Its technical sophistication is modest — Python's ssl stack is a liability at the JA3 layer — but the operational model (no VPS, trivial rotation, multi-account load-balancing, same-GFE frontage to `script.googleusercontent.com`) is uniquely suited to a "blackout with Google unblocked" regime. It is also the most **brittle to a single DPI upgrade**: the day Iran starts JA3-classifying traffic to AS15169, every install dies simultaneously.

**The most foundational technically, and also the most obsolete-by-signature.** FakeSNI's out-of-window stale-segment trick is an elegant exploit of the documented statelessness of Iranian DPI (Bock FOCI 2020). It **doesn't MITM**, doesn't break cert pinning, doesn't need a CA install — it just hands the DPI a poisoned SNI while the real server silently discards the decoy. But the trick's packet-pattern is **fingerprintable in one signature**, its upstream dependency on a specific Cloudflare IP creates an IP-block cliff, and it lacks every modern complement — ECH, IPv6, QUIC, DNS hardening, strategy diversity — that real-world tools like `zapret` or `GoodbyeDPI` carry. It is a thin, recent Claude-authored Go port of a Python original, useful as a pre-proxy in front of VLESS/REALITY but not a general-purpose bypass.

**The composition that actually works in April 2026.** Users who survive the current blackout windows run combinations: **FakeSNI (or equivalent TCP-fragmentation outbound) in front of a VLESS+REALITY client**, optionally **augmented with MITM-DomainFronting rules** inside Xray for specific CDN-hosted origins, with **MasterHttpRelayVPN as an emergency fallback** when everything else is IP-swept. No single tool here is sufficient; each patches a different layer of a filter that has shown, repeatedly since the June 2025 Twelve-Day War, that it can escalate from SNI filtering to protocol whitelisting to near-total closed-loop NIN mode in hours. The collective GitHub response — serverless, LLM-ported, Telegram-distributed, burn-and-replace — mirrors the filter's volatility. These three repositories are three snapshots of that arms race as of the 22 April 2026 checkpoint.

