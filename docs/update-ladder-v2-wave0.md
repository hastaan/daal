# Update ladder v2: wave 0 observations (read-only part)

The checks from `docs/update-ladder-v2.md` §7 "Wave 0" that need no publishing and no
account. Run on 2026-11-22 between 16:24 and 16:26 UTC, from the development laptop
(its own network, **not** an Iranian one), curl 8.18.0 (OpenSSL 3.5.5,
nghttp2 1.68.0). Plain GETs only. Nothing was created, tagged or published.

A vantage outside Iran says what the services do. It says nothing about whether an
Iranian network lets the request through; that is §8 of the study (the network test).

The test module is `github.com/sagernet/sing-box`: public, has a `go.mod`, and has many
pre-release tags (`-alpha.N`, `-beta.N`, `-rc.N`). Its newest tag at the time was
`1.15.0-alpha.13` (Go version `v1.15.0-alpha.13`), tagged 2026-10-24T01:08:35Z
according to `tags.atom`.

## 1. Google front: `www.google.com` serving other authorities

TLS goes to `www.google.com` (SNI and certificate `CN=www.google.com`; curl puts the URL's
host in SNI). Only the `Host` header, or `:authority` over HTTP/2, names the other
service.

```
M=github.com/sagernet/sing-box
curl -sS --http2   -H 'Host: proxy.golang.org' "https://www.google.com/$M/@v/list"
curl -sS --http1.1 -H 'Host: proxy.golang.org' "https://www.google.com/$M/@v/list"
curl -sS -H 'Host: proxy.golang.org' "https://www.google.com/$M/@v/v1.15.0-alpha.13.mod"
curl -sv -o /dev/null -H 'Host: proxy.golang.org' "https://www.google.com/$M/@v/list"   # handshake lines
curl -sS --http2   -H 'Host: amp-dev.cdn.ampproject.org' https://www.google.com/c/s/amp.dev/
curl -sS --http1.1 -H 'Host: amp-dev.cdn.ampproject.org' https://www.google.com/c/s/amp.dev/
curl -sS -H 'Host: cdn.ampproject.org' https://www.google.com/v0.js
```

| Request | Result |
|---|---|
| `proxy.golang.org` `@v/list` through the front, HTTP/2 | **200**, 8021 bytes, h2, server address 142.251.150.119. Byte-identical to the direct `https://proxy.golang.org/…/@v/list` (601 versions) |
| the same, HTTP/1.1 | **200**, 8021 bytes, identical |
| `.mod` of `v1.15.0-alpha.13` through the front | **200**. Byte-identical to `raw.githubusercontent.com/SagerNet/sing-box/v1.15.0-alpha.13/go.mod`, **comments included** (the file has 114 `//` comments) |
| Handshake | TLS 1.3, X25519MLKEM768, ALPN h2, certificate `CN=www.google.com` |
| `amp-dev.cdn.ampproject.org/c/s/amp.dev/` through the front, HTTP/2 and HTTP/1.1 | **200**, `text/html`, 139913 bytes, the cache's transformed AMP page (`transformed="google;v=8"`); same size as the direct request |
| `cdn.ampproject.org/v0.js` through the front | **200**, 284578 bytes |

**Answer: yes, both authorities are served behind `www.google.com` today**, over HTTP/2
and HTTP/1.1, with no redirect. The `.mod` answer keeps `go.mod` comments, so a full
note in comments would arrive intact.

## 2. Pre-release tags in the readers

```
curl -sS https://github.com/SagerNet/sing-box/tags.atom
curl -sS https://proxy.golang.org/$M/@v/list
curl -sS https://goproxy.cn/$M/@v/list
curl -sS https://goproxy.io/$M/@v/list
curl -sS https://mirror-go.runflare.com/$M/@v/list
curl -sS https://data.jsdelivr.com/v1/packages/gh/SagerNet/sing-box
```

| Reader | HTTP | Versions | Pre-release | `…-alpha.13` (newest) |
|---|---|---|---|---|
| GitHub `tags.atom` | 200, 5289 bytes | 10 entries (the feed holds the newest 10 only) | 7 of 10 | yes, first entry; titles are the tag names without `v` |
| `proxy.golang.org` | 200 | 601 | 443 | yes |
| `goproxy.cn` (47.246.44.192) | 200 | 601 | 443 | yes (same set; only the final newline differs) |
| `goproxy.io` (104.21.16.152, Cloudflare) | 200 | 601 | 443 | yes, byte-identical to proxy.golang.org |
| `mirror-go.runflare.com` (195.214.235.194) | 200 | 601 | 443 | yes, byte-identical |
| jsDelivr `data.jsdelivr.com` | 200 | 638 | 482 | yes, first; versions without the `v` |

**Answer: pre-release tags appear in every reader.** Two shapes to remember: the Go
proxies list versions as `vX.Y.Z-pre` in no particular order, jsDelivr and `tags.atom`
as the tag name with no `v`, newest first. `tags.atom` holds only the last 10 tags, so
a reader must not depend on an old tag being in it.

**Not answered here (needs a publish):** how long after a new tag each reader lists it.
The tag above is four weeks old, so it measures nothing about lag.

## 3. Iranian mirrors: reachable for a plain read

```
DA='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'
curl -sS <url> [-H "$DA"]          # one GET each, 25 s timeout, 16:25 UTC
curl -sS -D - -o /dev/null https://<docker host>/v2/   # the WWW-Authenticate realm
```

| Host and path read | Result | Address |
|---|---|---|
| `mirror-npm.runflare.com/left-pad` | 200, packument | 195.214.235.194 |
| `mirror-pypi.runflare.com/simple/requests/` | 200, simple index | 195.214.235.194 |
| `mirror-docker.runflare.com/v2/library/alpine/manifests/latest` | **200 with no token**, OCI index | 195.214.235.194 |
| `mirror-go.runflare.com/…/@v/list` | 200 | 195.214.235.194 |
| `mirror-linux.runflare.com/` | 200 | 195.214.235.194 |
| `package-mirror.liara.ir/repository/npm/left-pad` | 200 | 185.208.181.186 |
| `package-mirror.liara.ir/repository/pypi/simple/requests/` | 200 | 185.208.181.186 |
| `docker-mirror.liara.ir/v2/` | 401, `Bearer realm=…/service/token` (Harbor) | 185.208.181.183 |
| `mirror.abrha.net/repository/npm/left-pad` | 200 | 130.185.79.99 |
| `mirror.abrha.net/repository/go/…/@v/list` | 200, 601 versions incl. `-alpha.13`, **7.0 s** (a pull-through fetch; the others answered in under 1 s) | 130.185.79.99 |
| `mirror.abrha.net/repository/pypi/simple/requests/` | 200 | 130.185.79.99 |
| `docker.arvancloud.ir/v2/` | 401, `Bearer realm=https://docker.arvancloud.ir/v2/token` | 185.143.233.134 |
| `mirror.arvancloud.ir/` | 301 to `www.arvancloud.ir/dev/linux-repository` | 185.143.234.134 |
| `hub.hamdocker.ir/v2/` | 401, Artifactory realm | 185.53.140.21 |
| `docker.kernel.ir/v2/library/alpine/manifests/latest` | **200 with no token** | **51.91.99.11, an OVH address in France** |
| `focker.ir/v2/` | 401, `Bearer realm=https://focker.ir/v2/token` | 185.166.104.6 |
| `docker.iranserver.com/v2/` | **timed out** (25 s, no connection) | — |
| `mirror.kargadan.ir/` | 200 | 91.186.193.197 |
| `registry.docker.ir/v2/` | 401 | 136.243.12.202 (Hetzner, Germany, as the study says) |
| `repo.iut.ac.ir/` | 200 | 176.101.51.199 |
| `http://ir.archive.ubuntu.com/ubuntu/dists/noble/Release` | 200 | 217.198.190.6 |
| `ubuntu.pishgaman.net/` | 301 to `/cdimage/` | 185.126.0.250 |
| `mirror.iranserver.com/` | 200 | 185.255.89.114 |

**Answer: every mirror named in the study answered a plain read from here except
`docker.iranserver.com`** (timed out). Two corrections to the study's table:
`docker.kernel.ir` resolves, from here, to an OVH address in France, so like
`registry.docker.ir` it is likely useless in a cut (check its address from inside Iran
before counting it); and a 401 from `/v2/` is the normal first step of the token
handshake, not a refusal (the anonymous token step was not taken here).

## 4. Needs the owner

These need an account, a repository, a tag, a package or a published page, so they were
not run:

- **Lag of each reader after a new tag**: publish a pre-release tag on a throwaway
  repository with a `go.mod`, then poll `tags.atom`, the four Go `@v/list`, jsDelivr's
  list and `.mod`, and record when each first shows it (needs a GitHub repository).
- **A full note in `go.mod` comments through the proxy** for our own module (the
  comment pass-through itself is shown above on someone else's module).
- **Each Iranian mirror's cache behaviour**: publish v1, read it through the mirror,
  publish v2, poll; record how long v1 and a 404 are served. Same for a rewritten
  Docker tag (needs a Docker Hub account and repository, an npm package, a Go module).
- **Manifest annotations through each Docker mirror; the npm `readme` through each npm
  mirror** (needs our own image and package).
- **npm token lifetime today** (needs an npm account).
- **AMP cache with our own origin**: a valid AMP page on an origin we control, read as
  `<origin-with-dashes>.cdn.ampproject.org/c/s/<origin>/<name>.html` through the front,
  and how long the cache serves a stale copy (needs a published page).
- **The canary and the probe zone of §8** (needs a domain or zone).
- **Anything from an Iranian vantage** (all of the above is from outside).
