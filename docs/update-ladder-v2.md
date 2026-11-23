# Update-carrier ladder v2

Adviser's design, 2026-11-22. No code was changed. This replaces the carrier table in
`docs/blackout-tier-plan.md` §3 ("The carrier ladder") and extends
`docs/optional-addons-plan.md` §4. It follows the owner's direction: GitHub is not the
happy assumption; use several pieces of infrastructure the country itself depends on; use
a ladder; keep the DNS path as the last hope.

Every claim about Iran is marked **OBSERVED** (a dated report or measurement, source in §9)
or **INFERRED** (my reasoning). Most observations are user reports on net4people, not
measurements. Nothing was found for September–November 2026 except one item (§9, Tasnim).

---

## 0. The answer in one page

1. **No foreign carrier survived every phase of 2026.** Google, GitHub, Let's Encrypt, PyPI
   and Cloudflare names were each opened and closed again within days or weeks (OBSERVED).
   The right design is therefore *one small sealed note, written once, readable through
   many hosts*, not a search for the one unblockable host.
2. **The "packages" idea is half right.** Iranian mirrors of npm, PyPI, Docker Hub and the
   Go proxy are pull-through caches: in normal connectivity a package published upstream
   was readable through them two minutes later (OBSERVED 2026-11-22, from outside Iran).
   They stay reachable inside the national network during cuts (OBSERVED in use, April
   2026). **But during the cuts they mostly stopped receiving new upstream content**:
   data-centre egress was closed for weeks, about 0.017% of Iranian addresses could reach
   out, and developers called the mirrors "months out of date" (OBSERVED). So they are a
   good middle rung (blacklist and partly whitelist phases) and not the blackout answer.
   Whether any one mirror's egress was allowlisted during a cut is unknown and is the
   first thing the network test should measure (§8).
3. **The keystone is a git tag.** One push of a tag to a GitHub repository (with the token
   the `ghpages` backend already holds) is readable on `github.com`, on
   `raw.githubusercontent.com`, on four jsDelivr hostnames, on `proxy.golang.org` and two
   other public Go proxies, and on the Iranian Go mirrors. One write, about ten reader
   hosts on five unrelated networks, no new account.
4. **Google gets a second and third door** that need no Google account and have no script
   quota: the AMP cache and `proxy.golang.org`, both read through the existing
   `www.google.com` front (fronting to these two hosts is INFERRED and must be checked
   from outside first, §7 wave 0).
5. **DNS carries only the 16-byte standby key**, as plain A records at derived names, read
   through whatever resolver the network handed the phone. It is the only automated
   carrier with evidence of working in the first days of a near-total cut, and it had
   stopped working through the big resolvers by April 2026 (OBSERVED).
6. **In a true near-total cut nothing automated is dependable.** What is left is the open
   standby already in the pack, the DNS note while resolvers still recurse, and a human
   passing 26 characters. The 26-character key should be *wrapped* (§3.4) so it can go
   over SMS, a domestic messenger or a phone call without showing the address.
7. **Nothing can be written to** Windows Update, Apple, Play services, OCSP/CRL, NTP or
   connectivity checks. They are dismissed (§5).

---

## 1. Regimes and what was seen in each

| Regime | When (OBSERVED) | What passed |
|---|---|---|
| **R1 blacklist** (normal) | most of 2025; after 26 May 2026 in part | Anything not on the blocklist. Cloudflare, Azure, GCP, Akamai ranges are filtered by SNI, not swept. `*.workers.dev` sinkholed. Docker Hub and Google Cloud refuse Iranian addresses themselves (sanctions) |
| **R2 protocol whitelist, few destinations** | June 2025, 12 days | DNS/HTTP/TLS-shaped flows only. One Google address (`216.239.38.120`) stayed open, and `api.github.com` (`140.82.121.6`). DNS: "only A records return, TXT no response" |
| **R3 address/SNI whitelist** | about 17–27 Jan 2026; mid-April to mid-May 2026; after 26 May | Google Search, Gmail, Meet, Maps, Play Store, App Store, Apple, Samsung, Bing, Outlook, ChatGPT, GitHub, PlayStation (January). GitHub added mid-April, removed about 14 May. `pypi.org` reachable 1 May. Let's Encrypt opened about 12 April, removed 19 May. On Cloudflare addresses a strict SNI list (ChatGPT, later `hcaptcha.com`); other names cut after about 6 packets. Enforcement is a **source-address allowlist** (universities near 100%, home lines under 2%) plus destination filtering plus an SNI list |
| **R4 near-total cut** (national network only) | 8–17 Jan 2026; 28 Feb to April 2026 | Domestic services. Rubika throughout; Bale partly. SMS cut on 8 Jan, state bulk SMS continued. DNS tunnels over plain UDP/53 worked on 15 Jan; a 101-character query-name cap appeared 13–17 Jan; by 25 April tunnels failed through `8.8.8.8`, MCI's `10.202.10.10`, Shecan and TCI's resolver |

The censor's own playbook (the Jalili report in `research/intel-and-some-working-methods.md`)
says what to expect next: stage two is "granular whitelisting as a combination of FQDN, IP
prefix and port", opened on mobile operators first "to identify the violator within 48
hours"; foreign CDNs get no access at first; in crisis mode vital sites shrink to "only
email and basic search"; all resolvers are forced to the national DNS; file transfer in
domestic messengers is capped at 5 MB and scanned. Two consequences for us: a carrier that
lives on *the same name and address* as a service the state needs (Google search, Gmail)
outlasts one on a neighbouring name; and the first days of any reopening are when a
recipient's unusual fetch is most likely to be looked at.

---

## 2. The ladder

Rank is by reach across regimes, safety for the recipient, and work. "Reach" names the
regimes where there is evidence or a sound reason to expect the carrier to pass.

| # | Carrier | Note it carries | Reach | Recipient risk | State | Size |
|---|---|---|---|---|---|---|
| 0 | Standby address or CDN route already in the pack | none (zero fetch) | R1; R2/R3 only if the relay's range is allowed | none new | built | — |
| 1 | **Git tag**, read on `github.com` and `raw.githubusercontent.com` | micro in the tag name; full in a file | R1; R2 (`api.github.com` only, 2025); R3 on and off | low: GitHub logs abroad | new | S–M |
| 2 | **Google front.** Door 1 Apps Script (built). Door 2 AMP cache. Door 3 `proxy.golang.org` (reads the same git tag) | full / full / micro + full | R1; R2 (the one Google address); R3 whenever Google search is open | low: Google logs abroad | door 1 built; doors 2–3 new | M |
| 3 | **DNS micro-note** through the link's own resolver | micro only (16 bytes, A records) | R1–R3; early R4 | medium: the national resolver logs the name | new | M |
| 4 | **Global readers of the same tag/package**: jsDelivr (4 hosts), unpkg, `proxy.golang.org` direct, `goproxy.cn`, `goproxy.io`, `registry.npmmirror.com`; upstream npm and PyPI | micro + full | R1; R3 unknown (PyPI seen once) | low | new, readers only | S each |
| 5 | Ordinary mirrors: r2, ghpages, ipfs | full | R1 only | low | built | — |
| 6 | **Domestic pull-through mirrors** of Docker Hub, npm, Go, PyPI (Runflare, Liara, Parspack, ArvanCloud, Hamdocker, Kargadan) | micro + full | R1; R3 if that mirror's egress is allowlisted; R4 reachable but frozen | **high, see §4.6**: logged by operators tied to the state | new, opt-in | M |
| 7 | **Human courier**: `.sbpx` by email or any app; wrapped 26-character key by any means, SMS and voice included | full / micro | all, R4 included | depends on the channel; wrapped key shows no address | `.sbpx` built; wrap new | S |
| 8 | Search-engine snippet (the wrapped key on a page Google/Bing index) | micro | R3 crisis mode ("email and basic search") in theory | low | spike only | S–M |
| 9 | DNS tunnel | it is a route, not an update carrier | early R4 | high: sustained, identifying | research spike in `exotic-transports-plan.md` | L |

**Walk order after a route dies** (the C0 failure walk and the person's button; the
scheduled poll keeps using rung 5 only, through the tunnel): 0 → 5 (as today, random
order) → 1 → 2 → 4 → 3 → 6 (only if switched on) → the app asks for 7. DNS sits late in
the walk although it ranks high, because it can only reveal the standby and because its
names are logged at home. Limits for one walk: at most 8 TCP connections and 6 DNS
questions, 120 s, one host per class, a class that failed twice on this network is
skipped for 6 hours, and the walk stops at the first note that verifies as newer. Each
new host waits 2–10 s after the previous one. This keeps the existing floors
(`DefaultFailureFloor` 10 min, `MaxFailureFloor` 1 h, the per-network stamps in
`core/refresh/relaypack_recover.go`).

---

## 3. Notes, sealing and names

### 3.1 Two notes only

- **Micro note, 16 bytes.** The standby key (`salt ‖ ipv4`, `specs/relaypack-v1.md`
  "`_standby` key"). It authenticates itself against the signed `_standby.commit`, so it
  needs no signature and no MAC.
- **Full note.** The `daal-refresh-v2` container exactly as specified (freshness document,
  optional inline pack up to 48 KiB, optional standby key; 64 KiB in all), sealed. Its
  parts are verified as today: signature chain, `sequence` high-water mark, `not_after`,
  pack hash. The seal adds secrecy, never trust.

No third format. A signed 84-byte address hint under a pinned `hint_pub` (blackout plan,
claim 24) stays possible later; with a sealed standby and a full note it is not needed
now.

### 3.2 The secret

A new 32-byte `update_secret` travels in the **encrypted, per-recipient half** of the
`.sbpx`, beside the stored endpoint and `_standby`; never in the public signed skeleton
and never in `EngineFamilyConfigKeys`. The publisher keeps one root and derives:

```
u = HKDF-SHA256(update_root, salt = "daal/update-v2", info = relay_pack_id ‖ 0x0A ‖ audience)
```

Two audiences by default: `people` (every file made for a named person; they share one
`u`, so one write serves the family) and `everyone` (the Everyone file, whose secret must
be assumed known to the censor). A note written for `people` is unreadable and
unfindable with the Everyone file. Telling the Everyone audience is a separate, explicit
publisher choice, and the card says it tells the censor too. Per-recipient secrets
(`audience = recipient_fp_hex`) are allowed by the same formula; §4.6 explains why they
buy less than they seem to.

### 3.3 Names, keys, epochs

```
name(c, e)  = base32lower( HKDF(u, "name" ‖ c ‖ e)[0:10] )          16 characters
key(c, e)   = HKDF(u, "key"  ‖ c ‖ e)                               32 bytes
pad(c, e)   = HKDF(u, "pad"  ‖ c ‖ e ‖ standby_commit)[0:16]        micro keystream
```

`c` is the carrier label (`gittag`, `dns`, `amp`, `docker`, `npm`), so the same note looks
different on every carrier and cannot be matched across them. `e` is the epoch:
`floor(unix_time / 7 days)` for carriers whose names can be reused or deleted (git tag,
DNS, AMP page, Docker tag), `floor(unix_time / 28 days)` for write-once registries (npm,
PyPI). A recipient tries `e` and then `e−1`. The epoch bounds how long a name learned
from a seized phone stays useful, and it bounds negative caching.

- **Micro seal:** `sealed = standby_key XOR pad(c, e)`, 16 bytes, no tag. The recipient
  XORs and checks the result against the signed commit; anything else is "nothing new".
  Binding the commit into the pad means a keystream is never reused for a different key.
- **Full seal:** XChaCha20-Poly1305 with `key(c, e)`, a random 24-byte nonce in front,
  plaintext padded to 4, 16 or 64 KiB. Base64 where the carrier wants text. The
  container's `slot` member is set to `name(c, e)` so a note copied to another name is
  refused, as today.
- **Always present, constant size.** At the start of each epoch the publisher's app
  writes filler (random bytes of the same size) at the next name. A reveal then replaces
  filler with a note. An observer who knows the name cannot tell "nothing yet" from
  "moved", and a pull-through cache never stores a 404 for a name that a recipient asked
  for too early. If the app was not opened that epoch the name is created at reveal
  time, and the note is simply later on caching readers.

What a censor can and cannot do: without `u` it cannot find the names or read the notes,
so it cannot harvest addresses in bulk from any carrier. With `u` (a seized phone, or the
Everyone file) it reads what that audience reads, exactly as it can today with the mirror
URLs in a pack; it still cannot forge anything, because the micro note must match a
signed commit and the full note carries the publisher's signatures.

### 3.4 Wrapped standby key (do this first; it is small)

Today the 26 characters a person types are the address in the clear. Show and accept a
second form: `standby_key XOR HKDF(u, "wrap" ‖ standby_commit)[0:16]`, the same 26
characters in the same groups. It is useless to anyone without that audience's file, so
it may pass through SMS, Bale, Rubika, a voice call or a note on paper. The app accepts
either form (try plain, then unwrap; the commit decides). The Everyone audience keeps
the plain form only.

---

## 4. The carriers

### 4.1 Git tag (rung 1, and the write behind rungs 2c, 4 and part of 6)

**Why the censor keeps it.** GitHub is what Iranian software firms cannot work without.
OBSERVED: `api.github.com` stayed open in June 2025; GitHub was on the January 2026
whitelist; `github.com`, `api` and `raw.githubusercontent.com` were open 19–22 April 2026
while release assets and `objects` were blocked; added to the whitelist mid-April and
removed about 14 May. So: R1 yes, R2/R3 intermittent, R4 no. `*.github.io` (Fastly) is a
different name on ranges that were blocked in May 2026; today's `ghpages` backend is
therefore an R1 carrier only.

**Write.** One repository per relay under the publisher's GitHub account, named
`name(gittag, e)`-shaped (a new one each epoch is not needed; the *tag* carries the
epoch). Through the REST API with the fine-grained token the `ghpages` backend already
stores: commit one file `n` (the sealed full note, base64) and a `go.mod` whose comment
lines hold the same base64, then create tag `v0.<seq>.0-<26 base32 characters of the
sealed micro note>`. Plain HTTPS calls, automatable from the phone, free. Ties: the
GitHub account (email; GitHub sees the publisher's address unless the publisher is on a
VPN). The owner or repository name is visible in every reader's URL, so use an account
that exists only for this.

**Read.** All plain GETs, SNI equal to Host, no redirect:

| Host | Path | Gives |
|---|---|---|
| `github.com` | `/<o>/<r>/tags.atom` | tag names → micro note. Verified 200 from outside (blackout plan). About 2–30 KB |
| `raw.githubusercontent.com` | `/<o>/<r>/<tag>/n` | full note |
| `api.github.com` | `/repos/<o>/<r>/tags` | micro; 60 requests an hour per address, which carrier-grade NAT exhausts. Last choice |

**Fetcher.** `FetchRaw` can reach these today but with Go's TLS hello. Use the Chrome
hello and `h2mini` from `core/bootstrap/front.go` without the SNI/Host split (wave 1,
"browser GET"). Bounded read 64 KiB. Needs a small Atom tag extractor.

**Polling.** Failure walks only. One recipient makes at most two requests to GitHub per
walk; GitHub's own unauthenticated limits on `github.com` HTML/Atom are far above that.

**Near-total cut.** No.

**Work and test.** S–M. Worldbox: a fake `github.com` serving an Atom feed and a raw
file; scenarios "ghpages name blocked, github.com open" and "release assets blocked".
From outside today: confirm the pre-release tag shows in `tags.atom` and survives as
written.

### 4.2 Google front, three doors (rung 2)

**Why the censor keeps it.** Every Android phone talks to Google; search and Gmail are
named in the censor's own crisis list. OBSERVED: `216.239.38.120` stayed open in June
2025 (Drive, Gmail and the Play front reachable by pinning it); Google was on the January
2026 whitelist; near zero after 28 February; `www.google.com` at that address back about
19 April; Apps Script relays "started to work only after they whitelisted Google" and
were in daily use in April–May. No response aimed at Apps Script alone was found, only
whole-Google on and off. `script.google.com` by its own name was unreachable on some
networks (Irancell), which is why the front matters.

**Door 1, Apps Script (built).** Judgement: keep, and keep it last among Google doors
for the Everyone audience. Strengths: the publisher can write to it from the phone with
no stored Google credential; one fetch returns everything. Weaknesses: a Google account
bound to a phone number; a consumer quota (20,000 executions a day, 30 at once); the
whole class of script relays is now widely abused in Iran, so account suspension and a
quiet Google-side clamp are the likely ways it ends (INFERRED). Change proposed: seal the
container with `key("gas", e)` like every other note, so the script stores nothing a
Google reviewer or a leaked URL can read.

**Door 2, AMP cache (new).** The publisher puts a valid AMP page holding the sealed full
note (base64 in a `<p>`) on any HTTPS origin: the same GitHub repository through
`raw`/Pages, the publisher's zone, or R2. The recipient asks Google's AMP cache for it:
SNI `www.google.com`, `:authority <origin-with-dashes>.cdn.ampproject.org`, path
`/c/s/<origin>/<name>.html`. No Google account, no quota of ours, nothing for Google to
suspend except the origin's standing in the cache. INFERRED: fronting to
`cdn.ampproject.org` through `www.google.com` worked in 2022 (Fifield's AMP-cache
rendezvous) and should still; the cache serves stale copies for a while after a change,
so the name must be new for each note (it is: the epoch plus `seq` in the path). Note
that `core/rendezvous` already reserves an `amp_cache` slot; this is a freshness mirror
provider, not a rendezvous channel.

**Door 3, `proxy.golang.org` (new).** Google's Go module proxy serves any public GitHub
repository that has a `go.mod`: `/github.com/<o>/<r>/@v/list` returns the version list
(the micro note is in the version string) and `/@v/<version>.mod` returns the `go.mod`
bytes (the full note in comments). It is the git-tag write of §4.1 read through Google.
INFERRED and to be checked from outside: that the host answers behind the
`www.google.com` front, that pre-release versions appear in `list`, and how long `list`
is cached (expect minutes to half an hour).

**Known exposure, to check from outside (added 2026-11-22, unverified).** As far as is
known of the Go proxy, the first read of a module through `proxy.golang.org` (door 3 or
the direct reader of §4.4) puts its module path and versions in Google's public module
index (`index.golang.org`), permanently. The note tags have a distinctive shape
(`v0.<seq>.0-<26 base32>`), so anyone could list the note repositories read this way, and
the GitHub accounts behind them. They could not read a note, but they could report the
accounts or watch them. To check: does a first read through the front, or through the
direct proxy, appear in the index? The owner decides whether the Go-proxy readers stay on
by default; `goproxy.cn` and `goproxy.io` are not known to feed that index.

**Considered and not chosen as doors:** a published Google Doc, Blogger, Drive public
file (all need the publisher's Google credential on the phone to write, or manual
pasting; keep manual pasting of a sealed note into a "published to web" Doc as a
documented fallback only); `storage.googleapis.com` (Google Cloud refuses Iranian
addresses and needs a billing account); Firebase/FCM (not wired, and Play services ride
the dead tunnel; already dropped).

**Fetcher.** `FetchAppsScript` and `frontAttempt` exist. Needed: let the front take an
authority from a closed list (`script.google.com`, `*.cdn.ampproject.org`,
`proxy.golang.org`), with no redirect for the two new ones. At most two connections to
Google per walk stays the rule; the walk tries door 3, then 2, then 1, and stops at the
first note.

**Near-total cut.** No (Google search fell to near zero after 28 February).

**Work and test.** M in all. Worldbox: the Google-front fake already exists; add the two
authorities. Only an Iran vantage can say whether the Host switch to these authorities
passes where it passes for `script.google.com` (§8, D8–D9).

### 4.3 DNS micro-note (rung 3)

**Why the censor keeps it.** Every allowed service needs names resolved, and the
playbook forces all clients onto the national resolvers rather than switching DNS off.
OBSERVED: plain UDP/53 tunnels worked on 15 January 2026 while DoH/DoT did not; a
query-name cap between 101 and 102 characters from 13–17 January; "only A records
return, TXT no response" in June 2025; harsh rate limits on the foreign resolvers that
still answered; packets over a certain length dropped by internal name servers in March;
tunnels dead through the major resolvers by 25 April. INFERRED: in-country resolvers
recursed to foreign authoritative servers early in the cut and stopped or were filtered
later. No direct observation exists of national resolvers answering a *never-cached*
foreign name during a cut; that is check D1 in §8.

**Design, from that evidence.** A records only. Short names. Few questions. The 16 sealed
bytes are split over six names; each answer carries 3 bytes in its low 24 bits, and the
first octet is a fixed value from a short list of ordinary public /8s (so no answer
looks like a private or sinkhole address, which some resolvers drop):

```
<name(dns, e)[0:12]><i>.<zone>      i = 0..5      about 30 characters with a short zone
```

Six questions, one every 1–3 s, to the resolver the network gave the phone (never a
public resolver, never TXT, never EDNS tricks). TTL 300 s; the zone's negative TTL 60 s;
filler present from the start of the epoch. A cached answer is fine: the note does not
change within an epoch once revealed.

**Write.** The publisher's own zone. `publisher/deploy/cloudflare/dns.go` writes proxied
A/AAAA today; it needs an unproxied A-record writer for these names. So this carrier
exists only for publishers with the CDN add-on's domain (about $9–11 a year). A free
dynamic-DNS name would avoid the domain but puts the note under a zone the censor can
drop at no cost; not recommended. Ties: registrar and Cloudflare account, as the CDN
add-on already states.

**Recipient risk.** The national resolver logs "subscriber X asked for
`k3f…2.example.org`". The name is derived and the answer is sealed, but the *zone* is
visible, it is the same zone for every recipient, and it is the CDN route's zone. Anyone
who learns the zone can ask the resolver operator who else asked. That is the same
exposure a recipient already has by connecting to the relay's address (§4.6), with one
difference: it remains in a domestic log. For that reason DNS comes after the foreign
carriers in the walk, and is off for the Everyone audience.

**Near-total cut.** The only automated carrier with a real chance, for the first days
and on some resolvers. Treat it as the owner said: weak, kept as the last hope.

**Work and test.** M. Recipient side: a resolver-from-host lookup (the blackout plan's
claim 22) and six questions with `miekg/dns`, already an indirect dependency and used in
`core/fieldprobe/dns.go`. Worldbox: a resolver profile with A-only answers, the
101-character cap, a per-client rate limit and "no recursion abroad"; the walk must end
in "nothing new" inside its budget in the last case.

### 4.4 Global readers of the same write (rung 4)

These cost one reader each once §4.1 exists, because they republish a GitHub tag or an
npm package without any action by the publisher.

| Reader | Host and path | Why it may stay reachable | Evidence |
|---|---|---|---|
| jsDelivr | `cdn.jsdelivr.net`, `fastly.jsdelivr.net`, `gcore.jsdelivr.net`, `testingcf.jsdelivr.net`: `/gh/<o>/<r>@<tag>/n`; tag list at `data.jsdelivr.com/v1/packages/gh/<o>/<r>` | Iranian websites load scripts from it; four CDNs behind one service | INFERRED. No report either way for either cut. A state centre told sites on 29 Oct 2026 to move to `.ir` and domestic hosting, so dependence on foreign CDNs is being reduced |
| Go proxies | `proxy.golang.org` (direct), `goproxy.cn`, `goproxy.io`: `/github.com/<o>/<r>/@v/list`, `/@v/<v>.mod` | developer infrastructure; the two Chinese-run proxies sit outside Western sanctions politics | INFERRED; none measured from Iran |
| npm (only if the npm write of §4.5 is built) | `registry.npmjs.org/<pkg>` (Cloudflare), `registry.npmmirror.com/<pkg>`, `unpkg.com/<pkg>@<v>/n`, jsDelivr `/npm/<pkg>@<v>/n` | as above | OBSERVED: npm and PyPI "almost impossible" on 26 April 2026 |
| PyPI | `pypi.org/simple/<name>/`, `files.pythonhosted.org` (Fastly) | as above | OBSERVED reachable 1 May 2026; Fastly ranges reported blocked 30 May |
| cdnjs | — | — | **Dismissed: cannot write.** Libraries are admitted by review |

Rule: one reader from this class per walk, chosen by `HKDF(u, device, day)` so a phone
does not sweep five developer hosts in a minute. All are plain browser-shaped GETs,
64 KiB bound. Size S per reader. Whether any of these names is on a whitelist in R3 is
unknown; the network test decides which are worth shipping (§8, D7, D8, D10, D11).

As built (2026-11-22): the ladder picks the one rung-4 reader with
`HKDF(newest held u, "ladder-reader" ‖ device salt ‖ UTC day) mod n` over the readers
that are usable, not struck and fit the walk's budget; the device salt is 16 random bytes
kept on the phone and never sent. The Go-proxy readers carry the index exposure noted
under door 3 (§4.2); whether they stay on by default is the owner's decision.

### 4.5 Package registries as a write (feeds rungs 4 and 6)

Ranked by how well they suit us:

1. **Git tag → Go proxies.** Covered above. No registry account, no registry terms to
   break; it is an ordinary repository.
2. **Docker Hub tag.** Free account (email only), personal access token, public
   repository `<user>/<name>`. Write with the registry API (blob upload, manifest PUT),
   plain HTTPS, automatable from the phone. The sealed note goes in the image config
   blob (full) and in a manifest annotation (micro), so one manifest GET returns the
   micro note. Tags can be rewritten, so one tag per epoch. Docker Hub itself refuses
   Iranian addresses, which is exactly why Iran has more Docker mirrors than any other
   kind, including ArvanCloud's. Readers are therefore domestic only (§4.6).
3. **npm.** Free account, email, two-factor required. Note in the packument's `readme`
   (so one GET of `/<pkg>` returns it) and in a file `n` in the tarball. Versions cannot
   be replaced, names cannot be reused: one package per relay per 28-day epoch, a new
   version per note. From memory, to be verified: since late 2025 npm write tokens live
   90 days at most, so the publisher must renew a token on the phone every quarter.
   Registry terms forbid using npm as a data store; volume here is tiny, but removal as
   spam is possible. Build only if the test shows npm readers reach where Go and Docker
   readers do not.
4. **PyPI.** Dismissed for now: mandatory two-factor, name moderation, a general-hosting
   ban in the acceptable-use policy, and the note sits inside a wheel that the recipient
   must unzip. One domestic mirror (Parspack) returned 404 for brand-new projects.
5. **crates.io, Maven Central, Packagist, pub.dev, Homebrew.** Dismissed: few or
   unverifiable Iranian mirrors (a crates mirror timed out), identity-heavy publishing
   (Maven Central needs a verified namespace), or git-based indexes that mirrors copy on
   a schedule.
6. **Ubuntu/Debian archives, Launchpad PPAs, EPEL, Alpine.** Dismissed: we cannot write
   to the archives; Iranian apt mirrors are scheduled rsync copies of the official
   archives (7–18 hours behind on 2026-11-22) and do not carry PPAs.

### 4.6 Iranian domestic mirrors (rung 6): the "packages" question

**What exists** (OBSERVED alive 2026-11-22 from outside Iran unless noted):

| Operator | Hosts | Kind |
|---|---|---|
| Runflare | `mirror-npm.runflare.com`, `mirror-pypi.runflare.com`, `mirror-docker.runflare.com`, `mirror-go.runflare.com`, `mirror-linux.runflare.com` | pull-through in behaviour (docs say "periodic"); Docker manifest readable with no token |
| Liara | `package-mirror.liara.ir/repository/{npm,pypi/simple}`, `docker-mirror.liara.ir` | pull-through (Artifactory; stated in its FAQ) |
| Parspack | `mirror.abrha.net/repository/{npm,go,pypi/simple,…}` | npm pull-through; PyPI unclear |
| ArvanCloud | `docker.arvancloud.ir`, `mirror.arvancloud.ir` | Docker pull-through (INFERRED from standard registry-mirror use); distro mirrors by rsync |
| Hamdocker | `hub.hamdocker.ir` | Docker pull-through (INFERRED, Artifactory) |
| others | `docker.kernel.ir` (no token), `focker.ir`, `docker.iranserver.com`, `mirror.kargadan.ir` (a Nexus group over several of the above) | Docker / mixed |
| not domestic | `registry.docker.ir` resolves to a Hetzner address in Germany | useless in a cut |
| university / ISP apt | `repo.iut.ac.ir`, `ir.archive.ubuntu.com`, `ubuntu.pishgaman.net`, `mirror.iranserver.com` | rsync of official archives; nothing we can write to |

**Does a newly published upstream version appear on them?** In normal connectivity, yes,
by exact name on first request: npm packuments published at 15:49 UTC were served by
Runflare and Parspack at 15:51; brand-new PyPI projects answered on Runflare and Liara; a
non-library Docker repository answered on Runflare and `docker.kernel.ir`; Go `@v/list`
works on Runflare (all OBSERVED 2026-11-22). Not known: how long each mirror caches a
packument, a tag or a 404 before asking upstream again (Artifactory and Nexus defaults
are hours to a day; INFERRED). Measurable from outside today (wave 0).

**Do they stay reachable inside the national network during a cut?** Yes. OBSERVED:
Zoomit's 26 April 2026 guide tells developers to use `mirror.abrha.net` because npm and
PyPI were "almost impossible"; Liara advertises "without needing international
internet". INFERRED for the rest from where they are hosted.

**Do they keep syncing from upstream during a cut?** Mostly no. OBSERVED:
- June 2025: "all datacenters had become Iran-access only", with one unnamed exception.
- January 2026: data-centre international bandwidth still closed after 18 days (a
  hosting company's incident log, about 24 January); address ranges of *selected
  businesses* inside data centres were given international access one by one (Zoomit,
  12 January).
- 28 February–26 May 2026: about 2,000 Iranian source addresses (0.017%) could reach
  out; universities almost fully allowed. After 26 May about 8,000, "mostly ArvanCloud
  ASNs"; data-centre ISPs "continue to have restrictions". ArvanCloud's CEO on 30 May:
  data-centre internet "has not been reconnected", the Debian repository and whole
  Fastly ranges blocked.
- A developer's account (May 2026): domestic mirrors "months out of date", "throttled",
  "half-broken", teams living on pre-cut stashes. A mirror list's README: "Some mirrors
  are caches. They only have packages someone downloaded before the shutdown."
- No operator statement about sync during cuts was found. No report was found of a
  package published *during* a cut appearing on a mirror.

INFERRED conclusion: a pull-through mirror is exactly as fresh as its own egress. In R4
it serves what it cached before the cut. In R3 a mirror whose egress address was
individually allowlisted (ArvanCloud is the likeliest) would fetch a new note on
request, and upstream must also be among the destinations open to it (Docker Hub and npm
sit on AWS and Cloudflare; "some AWS IPs worked"). That is two unknowns multiplied. It
is worth one rung because, when it does work, it reaches recipients on home and mobile
lines that have no foreign access at all, which nothing else on this ladder does.

Pre-placing notes before a cut gains nothing: a note the recipient can already read
before the cut is the same as an open standby in the pack.

**Danger to the recipient. Read before building.**
- The operators are Iranian companies under Iranian law; ArvanCloud is sanctioned abroad
  for its part in building the national network. Assume request logs (address, port,
  time, path) are available to the state.
- A phone on a mobile line asking a developer mirror for a Docker manifest or an npm
  packument is unusual. A laptop is not.
- The path names the publisher's namespace (`<user>/<repo>`, the package's maintainer,
  the Go module's GitHub owner). Whoever learns one name can list everything under that
  namespace and ask the mirror who fetched any of it. Per-recipient names do not prevent
  this, because the namespace links them.
- Measured against what a recipient already risks: someone holding the pack already
  knows the relay's address and can find its clients in border flow records. The mirror
  adds a second, longer-lived, domestic record of the same fact. It does not expose a
  new fact to an adversary who has the pack, and it exposes nothing to one who has not.

Rules that follow: off by default; switched on per pack by the publisher, shown to the
recipient in plain words; never for the Everyone audience; at most one domestic mirror
per walk and only after every foreign rung failed on this network; never from the
scheduled poll; requests shaped like the real client's (Docker's `Accept` header, npm's
abbreviated-metadata `Accept`), since a browser-shaped request for a manifest is itself
odd.

**Fetcher.** Runflare and `docker.kernel.ir` answer a manifest GET directly. ArvanCloud,
Hamdocker, Focker and Liara answer 401 first and need the token handshake (one GET to
the realm in `WWW-Authenticate`, then the manifest with `Authorization: Bearer`): two
more requests and custom request headers, which `h2RequestHeaders` does not take today.
npm and Go mirrors are single GETs. Bound 64 KiB.

**Work and test.** M (Docker write backend, registry reader, consent copy). Worldbox: a
pull-through fake with a stale-cache switch and a 404-cache timer; scenario "mirror
reachable, upstream cut" must end as "nothing new" without spending the walk. Only an
Iran vantage, and only during a cut, can answer the sync question; the canary in §8
answers it with one request.

### 4.7 Public cloud object storage

- **Cloudflare R2 (built).** `*.r2.dev` or a custom name on Cloudflare addresses.
  Cloudflare ranges are open in R1 and SNI-filtered in R3 with a short allowed list, so
  R2 is an R1 carrier. Keep.
- **AWS S3, Azure Blob, Google Cloud Storage.** OBSERVED only generically: all three
  refuse Iranian customers under sanctions; "some AWS IPs worked on all protocols while
  others were blocked" (ArvanCloud CEO, May 2026). No report that any storage endpoint
  name was whitelisted. Each needs a billing account in the publisher's real name and a
  card. **Dismissed as a new write**; one status-only check in the network test (D15)
  tells us if that judgement is wrong.
- **ArvanCloud object storage.** **Dismissed, dangerous**: signing up needs Iranian
  identity verification, a publisher abroad cannot, and the operator works with the
  censor.

### 4.8 Update and security infrastructure

Windows Update, Apple software update and push, Android connectivity checks, Play
services, OCSP/CRL hosts, NTP: **we cannot write to any of them**, so they cannot carry a
note. They also were not reliably kept open: no evidence that any was whitelisted; a
user's clocks drifted with no NTP in April 2026; Let's Encrypt was unreachable from
Iranian servers for weeks, government sites showed certificate errors after 53 days, and
it was opened on about 12 April and closed again on 19 May (all OBSERVED). The press
advice in Iran was offline WSUS and mirrors. The useful lesson is negative: "banks need
it" did not keep certificate infrastructure open.

Two partial exceptions, both dismissed:
- **Certificate transparency.** We *can* write: issue a certificate for the publisher's
  zone whose extra names hold the sealed bytes. But no reader of CT (crt.sh, Cert
  Spotter, the logs themselves) is on any observed whitelist, the names stay in public
  logs for ever beside the publisher's zone, and it adds nothing the DNS note does not.
- **Play Store / App Store listing text.** Writable only through a developer account
  with verified legal identity, and changes wait hours to days for review. Useful for
  shipping the app, not for notes.

### 4.9 Messengers, email, SMS, Wikipedia

- **Email.** OBSERVED: Gmail was on the January whitelist and Outlook too; the playbook
  keeps "email and basic search" in crisis mode; Gmail was reported blocked on 26 April.
  Use it as the main **human** courier: the publisher shares the `.sbpx` (or the wrapped
  key) from the share sheet; the recipient opens it from Gmail. No code beyond the batch
  "send the new file to everyone" (C8). No automatic mailbox reading: it would put a
  mail credential in the app. Iranian mail providers: dismissed (state reach, no
  evidence they receive foreign mail in a cut).
- **Telegram.** Blocked since 2018; the public channel preview (`t.me/s/…`) is blocked
  by name. Dismissed as an automated carrier. It remains what families actually use once
  anything works, and the wrapped key suits it.
- **WhatsApp.** OBSERVED blocked since 8 January 2026. Human courier when it works.
- **Bale, Eitaa, Rubika, Soroush.** OBSERVED: Rubika worked throughout the cuts, also
  from abroad with an Iranian number; Bale partly. OBSERVED (OTF audit, December 2024):
  no end-to-end encryption, servers read messages, Rubika uploads contacts, Bale sends
  location at login; state ties documented. Accounts are bound to a SIM registered to a
  national ID. **Never automated, never suggested by the app.** If a family already
  talks there, the only thing that may cross is the wrapped key, and the app says so. A
  public channel on these platforms as an automated carrier (their web previews are
  readable inside the national network) is dismissed: the publisher would need an
  Iranian SIM identity, and the reader log sits with the censor's partner.
- **SMS.** OBSERVED: cut nationwide on 8 January, outbound-abroad restored about 17
  January, disrupted for hours on 28 February; no evidence about inbound international
  SMS. Cleartext to the operator, kept, bound to both SIMs. One message holds the 26
  characters. Human courier only, wrapped key only; the plain key over SMS hands the
  standby address to the operator.
- **Wikipedia.** One user report says it was reachable on 27 January 2026. Writing
  ciphertext into Wikipedia is vandalism of a commons and gets reverted. **Dismissed.**

### 4.10 Search snippet (rung 8, spike)

The crisis list keeps "basic search". A page on any origin with the wrapped key next to
a derived search phrase could be found by typing the phrase into Google or Bing; the
snippet shows the 26 characters. It needs no app support on the recipient's side at all
(a person can do it by hand). Unknowns: indexing delay (hours to days; Bing's IndexNow
may shorten it), snippet fidelity, Google's bot checks against automated queries, and
OBSERVED on 27 April 2026 Google search on the national network was "limited to domestic
content". Do a two-day measurement from outside before deciding. Low confidence.

### 4.11 DNS tunnel (rung 9)

A data route (`docs/exotic-transports-plan.md`, "DNS tunnel lifeline route"), not an
update carrier. Its place here: the pack should carry the tunnel route's domain and key
from day one, so *using* it needs no update; and once it is up, an ordinary refresh can
ride it. The evidence above (name cap, length drops, rate limits, dead through major
resolvers by late April) says text-only, for days, on some networks. Sustained queries
to one zone identify the user far more than six questions do.

### 4.12 The existing carriers, judged

| Carrier | Verdict |
|---|---|
| C0 failure walk | Keep. It is the engine every rung plugs into. Its shell wiring and worldbox run are still open (blackout plan) and come before any new rung |
| Standby Floating IP | Keep. Zero-fetch for one blocked address. Add the wrapped key |
| Apps Script through the front | Keep as door 1; seal its container; do not let it be the only Google door |
| GitHub Atom (planned C4) | Becomes §4.1; build it |
| ghpages | R1 only (`*.github.io` on Fastly). Keep for the scheduled poll; do not spend failure-walk budget on it once `github.com` reading exists |
| r2 | R1 only. Keep |
| ipfs | Weakest. Public gateways are slow and on no whitelist. Keep for diversity in the scheduled poll; skip it in failure walks |

All three ordinary mirrors serve the document and pack in the clear at URLs written in
the pack. Sealing them with the same scheme is a later, separate decision (§7 wave 4).

---

## 5. Dismissed, in one list

cdnjs (cannot write); PyPI, crates.io, Maven, Packagist, pub.dev, Homebrew (§4.5);
Debian/Ubuntu archives and PPAs (cannot write; mirrors do not carry PPAs); S3, Azure
Blob, GCS (billing identity, provider-side refusal, no whitelist evidence); ArvanCloud
storage and CDN (identity, cooperation); Windows Update, Apple, Play services, OCSP/CRL,
NTP, connectivity checks (cannot write, and not kept open); certificate transparency (no
reachable reader); app-store listing text (identity, review delay); FCM push (not
wired); Telegram and WhatsApp as automated carriers (blocked); Bale/Eitaa/Rubika/Soroush
as automated carriers (identity-bound, logged, state-tied); Iranian email; Wikipedia
(abuse); TXT and AAAA DNS records (TXT dropped in 2025; AAAA adds nothing over A);
public resolvers and DoH for the note (blocked or rate-limited; the link's resolver is
the unremarkable one); a 12-word code (cannot hold a signature; the wrapped 26
characters replace it); pre-placed notes in mirror caches (equal to an open standby).

---

## 6. What needs owner accounts or money

| Item | Who | Cost | Ties to identity |
|---|---|---|---|
| GitHub account for tags (per publisher) | publisher | free | email; already needed for `ghpages`. Use an account made for this |
| Domain + Cloudflare zone (DNS note) | publisher | about $9–11 a year | registrar and Cloudflare, as the CDN add-on. No domain, no DNS rung |
| Google account (door 1) | publisher | free | phone number; already in add-on 3. Doors 2 and 3 need none |
| Docker Hub account (rung 6) | publisher | free | email |
| npm account (optional) | publisher | free | email, two-factor, token renewal |
| **Project canary** (§8): one GitHub repository with a scheduled Action, one Docker Hub repository, one npm package, one AMP page | owner | free | a project account, not a person's |
| **Probe DNS zone** with a wildcard A record and short TTL | owner | about $10 a year | registrar |
| Standby Floating IP | publisher | €3.00 a month | none new |

No rung needs Daal to hold a credential that can spend money.

---

## 7. Build order

Lanes inside a wave touch disjoint files. C0's remaining work (shell wiring, worldbox
run) is assumed done first.

**Wave 0. Checks from outside Iran, no code in the tree (1–2 days).**
- Does `www.google.com` front to `proxy.golang.org` and `<x>.cdn.ampproject.org` today?
- Do pre-release tags appear in `tags.atom`, in Go `@v/list` (proxy.golang.org,
  goproxy.cn, goproxy.io, mirror-go.runflare.com) and in jsDelivr's version list, and
  after how long? Are `go.mod` comments returned intact by `.mod`?
- For each Iranian mirror: publish v1, read it through the mirror, publish v2, poll.
  Record how long v1 and a 404 are served. Same for a rewritten Docker tag.
- Does a manifest annotation survive each Docker mirror? Does the npm `readme` survive?
- npm token lifetime today.
- Set up the canary and the probe zone (§8).

**Wave 1. Foundations.**
| Lane | Files | Size |
|---|---|---|
| 1A spec | `specs/update-ladder-v2.md` (new); a short `_update` section in `specs/relaypack-v1.md` | S |
| 1B secret in the file | `bundle/go/bundle/update_secret.go` (new) and its tests; the publisher's `.sbpx` writer under `publisher/deploy/relaypack/` | S |
| 1C notes | `core/refresh/note.go` (new): names, keys, micro seal, full seal, padding. Pure, no sockets | S |
| 1D browser GET | `core/bootstrap/browserget.go` (new): Chrome hello + `h2mini`, SNI equal to Host, caller-supplied `accept` and `authorization` headers, bounded read; a header parameter in `core/bootstrap/h2mini.go` | S–M |
| 1E wrapped key | `bundle/go/bundle/standby_wrap.go` (new); UI copy in both shells (Farsi by the Farsi editor) | S |

**Wave 2. The keystone and the measurement.**
| Lane | Files | Size |
|---|---|---|
| 2A git-tag write | `publisher/deploy/freshness/backends/gittag/` (new) | S–M |
| 2B git-tag readers | `core/refresh/carrier_gittag.go` (new): Atom, raw, jsDelivr, Go-proxy list and `.mod` | M |
| 2C ladder | `core/refresh/ladder.go` (new): order, budget, strikes; the one edit to `walkEndpoints` in `core/refresh/relaypack_refresh.go` | M |
| 2D network test, carriers run | `core/fieldprobe/plan_carriers.go`, `core/fieldprobe/targets-v3.json`, `specs/field-probe-v3.md` (all new), report fields in `bundle-go/fieldreport` | M |
| 2E worldbox | fakes and scenarios under `test-rigs/worldbox/` (GitHub, Go proxy, jsDelivr, pull-through mirror, resolver profiles) | M |

**Wave 3. Decide from the first field reports, then build what passed.**
| Lane | Files | Size |
|---|---|---|
| 3A Google doors 2–3 | authority list in `core/bootstrap/front.go`; `core/refresh/carrier_googledoors.go` (new); `publisher/deploy/freshness/backends/amppage/` (new) | M |
| 3B DNS note | `publisher/deploy/cloudflare/dns_note.go` (new); `core/refresh/carrier_dns.go` and `core/bootstrap/dnsq.go` (new) | M |
| 3C Docker and domestic mirrors | `publisher/deploy/freshness/backends/dockertag/` (new); `core/refresh/carrier_registry.go` (new); consent and card copy | M |
| 3D seal door 1 | `publisher/deploy/freshness/backends/appsscript/`, `core/refresh/frontmirror.go` | S |

**Wave 4. Optional.** npm write and readers; sealing r2/ghpages/ipfs; the search-snippet
measurement; a signed micro hint under a pinned `hint_pub` if a second standby is ever
wanted.

---

## 8. The network test: what to add

`specs/field-probe-v2.md` already measures the Google front (B1–B3), the GitHub feed (B4)
and record types on cached names (A4, with the stated gap that a publisher-controlled
zone is needed). The additions below do not fit its budget (30 connections, 18
questions, five destination addresses, 4 minutes), so they form a **second run,
"carriers"**, with its own rate-limit slot (one per network per 12 h), no relay probes,
at most 14 connections and 12 DNS questions, 3 minutes, the same sequential, jittered,
no-retry shape and the same refusals.

**The canary.** A project-owned object whose content is the current UTC hour, rewritten
by a scheduled job every hour: a git tag and file, an AMP page, a Docker tag, an npm
version. Reading it through a host tells us in one request both *is this host reachable*
and *how old is what it serves*. The report stores the age in buckets (under 1 h, 6 h,
24 h, 7 days, older, unreadable). This is the direct measurement of "do the mirrors keep
syncing during a cut", and it works without any publisher's names.

| id | Check | Answers |
|---|---|---|
| D1 | A for `<12 random characters>.<probe zone>`, link resolver | does the resolver recurse to a foreign authoritative server for a name nobody cached (closes the A4 gap) |
| D2 | AAAA, CNAME, TXT for three more fresh labels | which record types survive |
| D3 | A for a fresh name of 60 characters, then one of 100 | the query-name cap |
| D4 | six A questions, 1–3 s apart, fresh labels | does a note-shaped burst pass, or meet a rate limit |
| D5 | `github.com` canary `tags.atom` (replaces B4's `golang/go` path) | reach and age |
| D6 | `raw.githubusercontent.com` canary file | reach and age |
| D7 | `cdn.jsdelivr.net` canary; on failure `fastly.jsdelivr.net`, then `gcore.jsdelivr.net` | which jsDelivr network passes; age |
| D8 | `proxy.golang.org` canary `@v/list`: direct, then through the Google front | reach; does the Host switch pass for this authority |
| D9 | canary AMP page through the Google front | same for the AMP cache |
| D10 | `registry.npmjs.org` canary packument; on failure `registry.npmmirror.com` | reach and age |
| D11 | `goproxy.cn` canary `@v/list` | a non-Western developer proxy |
| D12 | one domestic npm mirror, canary packument | reach from this line; **age = is the mirror syncing** |
| D13 | one domestic Docker mirror (ArvanCloud first), canary manifest | same, on the operator most likely allowlisted |
| D14 | one domestic Go mirror, canary `@v/list` | same |
| D15 | one object each on S3 and Azure Blob, status class only | was dismissing object storage right |
| D16 | B1 repeated against the pinned Google address when DNS gave none | is the one-address fallback alive |

**A decision the owner must take for D12–D14.** The target loader today refuses `.ir`
names and anything marked domestic. That rule is right for the main run. The carriers
run needs a separate, signed `domestic_mirrors` list, its own consent sentence ("this
also asks three Iranian developer mirrors for a public test package; those companies can
see that this line asked"), and D12–D14 are skipped without it. The canary names are
public and the same for every Daal user, so the request marks "runs Daal's test", not
"knows publisher P". If that is judged too much for a family phone, run D12–D14 only
from a developer's laptop in Iran.

**Only an Iran vantage can answer:**
1. Do national resolvers answer never-cached foreign names, per operator, and does that
   survive into a cut (D1–D4, and they must be run *during* one)?
2. Does the Google front pass the Host switch to `proxy.golang.org` and the AMP cache
   where it passes for `script.google.com` (D8, D9)?
3. Which jsDelivr hostname, if any, passes in a whitelist phase (D7)?
4. Is any domestic mirror's content fresh during a whitelist phase or a cut (D12–D14)?
   One fresh reading from ArvanCloud during a cut would move rung 6 near the top.
5. Is `github.com` open while `*.github.io` and `objects` are not, today (D5, D6)?
6. Does a phone on a mobile line get the same answers from the domestic mirrors as a
   data-centre host (some mirrors rate-limit or restrict by network)?
7. Inbound SMS from abroad during a cut, and whether a 26-character code is delivered
   unaltered: a family test, by hand.
8. Does the wrapped key survive Bale/Rubika/SMS unmangled (digits and letters only, five
   groups): by hand.

**Worldbox can answer:** walk order and budget; "reachable but frozen" mirrors; 404 and
stale-version caching; the six-question DNS note under an A-only, capped, rate-limited
resolver; the fetcher against 401-then-token registries; refusal of a note at the wrong
name, epoch or audience; that nothing in the walk runs while a route is up.

---

## 9. Sources

Repository: `research/intel-and-some-working-methods.md` (the Jalili report; Google
front and `216.239.38.120`; protocol whitelist); `docs/blackout-tier-plan.md` §3;
`docs/optional-addons-plan.md`; `docs/exotic-transports-plan.md` (DNS tunnel, DNS-TXT
courier, whitelisted couriers); `specs/relaypack-v1.md` (`daal-refresh-v2`, `_standby`);
`specs/field-probe-v2.md`; `core/bootstrap/{fetcher,front,h2mini}.go`;
`core/refresh/{relaypack_refresh,relaypack_recover,frontmirror}.go`.

Web, fetched 2026-11-22 by two research passes (the mirror probes were made from outside
Iran in normal connectivity and show design, not behaviour in a cut):
- net4people BBS issues #484 (June 2025), #561 (January 2026), #586, #612, #626, #630:
  https://github.com/net4people/bbs/issues/561 and siblings
- slipstream issue #16 (query-name cap): https://github.com/EndPositive/slipstream/issues/16
- arXiv 2603.28753: https://arxiv.org/html/2603.28753
- Filterwatch, January and February 2026 network monitoring:
  https://filter.watch/english/2026/01/28/network-monitoring-january-2026-from-regional-disuptions-to-total-blackout-and-whitelisted-access/ ,
  https://filter.watch/english/2026/03/06/network-monitoring-february-2026-a-new-phase-of-selective-internet-in-iran/
- IODA, tiered internet: https://ioda.inetintel.cc.gatech.edu/reports/from-war-to-sovereignty-the-normalization-of-tiered-internet-in-iran/
- Cloudflare, partial restoration May 2026: https://blog.cloudflare.com/iran-internet-partially-restored-may-2026/
- ASL19, blackout to whitelist: https://asl19.org/en/blog/2026-04-30-from-blackout-to-whitelist-the-anatomy-of-a-tiered-internet
- Zoomit: developer mirrors during the outage (26 April 2026)
  https://www.zoomit.ir/computer-learning/459207-bypass-internet-outage-developer-mirrors/ ;
  selective access (12 January 2026) https://www.zoomit.ir/iran-news/455534-selective-access-internet-restriction/ ;
  whitelist changes (27 January 2026) https://www.zoomit.ir/iran-news/455937-internet-connection-experiencing-some-changes/
- Digiato: ArvanCloud CEO (30 May 2026) https://digiato.com/iran-technology-news/the-internet-is-not-normal-yet-2 ;
  Let's Encrypt removed from the whitelist https://digiato.com/iran-technology-news/lets-encrypt-removed-from-internet-whitelist
- Khabaronline, GitHub added and removed: https://www.khabaronline.ir/news/2219335/
- Let's Encrypt community, renewals during the outage:
  https://community.letsencrypt.org/t/irans-internet-outage-and-challenges-for-renewing-letsencrypt-certs/246416
- Hosting incident log, Dey 1404: https://mizbanfa.net/support/emm-1404-dey/
- Developer account of the cut: https://dev.to/dalirnet/from-80-days-around-the-world-to-80-days-in-the-dark-1bkb
- Mirror directories and operator pages: https://github.com/MiravaOrg/Mirava ,
  https://mirrors.arash-hatami.ir/ , https://runflare.com/mirrors , https://liara.ir/mirrors/ ,
  https://mirror.kargadan.ir/ , https://github.com/imahdi1383/IranDevMirrors ,
  https://github.com/Ali30mhi/rahyab
- Internet Society Pulse, sanctions and provider-side blocking:
  https://pulse.internetsociety.org/en/blog/breaking-the-web-how-sanctions-are-undermining-irans-access-to-the-internet/
- Tasnim, foreign domains lost (9 November 2026):
  https://www.tasnimnews.ir/en/news/2026/11/09/3744064/us-restrictions-disrupt-iranian-websites-access-to-global-internet/amp
- OTF audit of Iranian messengers (December 2024; search snippet only):
  https://opentech.fund/wp-content/uploads/2024/12/Phase_II_Iranian_Msgs_Apps_Report.pdf

Stated from memory and not re-checked today: npm's 90-day write-token limit; Artifactory
and Nexus default cache periods; the 2022 AMP-cache fronting result; that Docker Hub
refuses Iranian addresses. Each is listed in wave 0 or §8 for checking.
