// Package vultr is the Vultr adapter: the SECOND live cloud a Daal
// relay can be built on, and therefore the thing that makes L5
// ("rotate provider") mean anything at all.
//
// # THE CHOICE, AND WHY IT WAS NOT A COIN FLIP
//
// Wave 6 inherited two half-built adapters — this one and
// providers/stark — and exactly one could be finished. Neither was
// usable: this package's live client returned ErrLiveNotImplemented
// from every method, and Stark's had a real REST transport but no live
// wiring. Lines of code were the least interesting difference.
//
// ## 1. Who the provider is (the criterion that settled it)
//
// Stark Industries Solutions is a real company, not a placeholder, and
// what is publicly known about it disqualifies it for this tool:
//
//   - It is the hosting provider most consistently named in open
//     reporting as a "bulletproof" host — one that markets its
//     tolerance of abuse complaints — and it was placed under EU
//     sanctions in 2025 over infrastructure used for pro-Russian
//     influence operations and DDoS against European targets.
//   - Its address space is, in consequence, among the most heavily
//     blocklisted on the public internet. A relay is worth nothing if
//     the recipient's network drops the prefix on reputation alone,
//     and Daal's threat model already assumes the adversary reads
//     public blocklists.
//   - Sanctions are not a footnote for the operator. A publisher in
//     the EU or UK paying a sanctioned entity has a personal legal
//     problem that has nothing to do with censorship, and this tool
//     must not create one silently.
//
// Putting an at-risk operator's relay — and every recipient who dials
// it — behind a provider whose selling point is that it does not
// answer complaints is not a neutral engineering default. It also
// inverts the property that makes a boring commodity host good cover:
// on a mainstream cloud a Daal relay looks like the thousands of
// ordinary VPSes around it; in bulletproof space, being there is
// itself the signal.
//
// Vultr (The Constant Company, LLC) is an ordinary US commodity host
// with an ordinary abuse process. State this plainly rather than
// pretending it is neutral either:
//
//   - US jurisdiction means US legal process and US sanctions law. A
//     relay hosted there is subject to both. It also means the account
//     itself cannot be paid for from inside Iran; the operator model
//     Daal assumes (a publisher outside, recipients inside) is the one
//     that works, and that is unchanged from Hetzner.
//   - Its abuse handling is real: a complaint can take a relay down
//     with notice, which is a liveness risk, not a safety risk, and it
//     is the same risk Hetzner already carries.
//   - It is large and generic, which is the cover property that
//     matters. Its ranges are not blocked wholesale today, but neither
//     Vultr's nor Hetzner's ranges are guaranteed to stay unblocked —
//     that uncertainty is precisely why the ladder has an L5 rung.
//
// What we do NOT know and are not claiming: whether any specific
// Vultr region is currently reachable from a given Iranian network.
// Nothing in this package has been run against a live Vultr account.
// Every claim below is about code, not about hardware.
//
// ## 2. What the ladder needs, and whether the provider has it
//
//	need                        Vultr                Stark
//	server create + user-data   yes (base64)         API is fictional
//	server destroy              yes                  "
//	cloud firewall              yes (groups + rules) "
//	floating IP (L3)            yes (reserved IPs)   "
//	pricing                     yes (/v2/plans)      "
//	region listing              yes (/v2/regions)    "
//
// The Stark column is not a judgement about the company's product; it
// is that the code in providers/stark talks to
// "https://api.starkindustries.example/v1" — the RFC 2606 example TLD.
// Every request shape in it was invented. Finishing it would have
// meant guessing an undocumented API and calling the guesses tested.
// Vultr publishes an API reference and an official SDK, so the wire
// shapes here can be checked against a document instead of a hope.
//
// ## 3. Dependency cost
//
// Vultr has an official SDK (github.com/vultr/govultr/v3) and this
// package deliberately does NOT use it. The live client is ~1 file of
// net/http against the documented /v2 REST surface, for three reasons:
//
//   - publisher/deploy is an audited tree: opsec_test.go forbids
//     net/http outside an explicit, per-file allowlist precisely so a
//     reviewer can enumerate every host this binary can reach. One
//     readable file is enumerable; a transitive SDK dependency tree is
//     not, and "the SDK only talks to the API" is a claim the test
//     cannot check.
//   - the tests the ladder needs are end-to-end against a fake HTTP
//     server (see live_client_test.go), which exercises the real
//     request and response shapes. An SDK-backed client tested through
//     a hand-written fake would test the fake.
//   - it is a supply-chain addition to a tool whose users are at risk,
//     for a REST surface small enough to read.
//
// The cost is honest and worth writing down: when Vultr changes its
// API, this file does not get fixed for us. The mitigation is that the
// surface used is small, versioned (/v2), and every response field
// this package reads is asserted in the fake-server tests.
package vultr
