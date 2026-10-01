# cproxy — Claude Context

> Rules and specification needed to recreate, extend, or debug the `cproxy` C++23 reverse proxy.
> Companion to `docs/specification.md`.
- DO NOT USE  real ip4/ip6/fqdn in code or in tests or any document going to git

---

## What this service is

`cproxy` is a **C++23 reverse proxy** — the edge between the ASP.NET frontend `fishfind.info` and the
internal backend droplets. It runs in Docker on **Debian 13 ("trixie")** on droplet
**159.89.113.225**. It gives `fishfind.info` one REST entry point and forwards inward.

- **Today:** fronts one upstream, `docapi` (droplet `68.183.196.166`,
  `../../efj-backend/service/docapi`) — requests under `/api/` are proxied there.
- **0.18.0 (DEPLOYED 2026-09-24, route live):** a second upstream, **waterapi**
  (`../../efcs-backend/service/waterapi`, station map) on the second backend droplet `137.184.218.128`
  (`debian-csnode`), for `/api/v1/water/*`. Off until `CPROXY_WATERAPI_UPSTREAM` is set. See
  "Second upstream: waterapi" below. The transport is VPC peering default-tor1 ↔ default-nyc1.

```
fishfind.info ──►  cproxy (159.89.113.225)  ──►  docapi   (68.183.196.166, VPC 10.118.0.3:8080)
                    /api/v1/water/* → waterapi   ──►  waterapi (137.184.218.128:8090)  [0.18.0, not deployed]
                    /api/*          → docapi
                    /health         → local
```

---

## Keeping docs in sync — IMPORTANT

**On every API change (a fronted endpoint added/removed/changed, or a change to `/health`,
`/health/ready`, `/metrics`), you MUST update BOTH:**

- **`docs/api-guide.html`** — the client-facing "Fish API Gateway" reference. Add/adjust the endpoint's
  section + table row, the nav link, and a quick-reference row; bump the `cproxy X · docapi Y — verified
  <date>` version banner and the `/health` version example. It is a full standalone HTML document (open
  in a browser, no build). Easy to forget because it's HTML, not markdown.
- **`docs/specification.md`** — the recreate-from-scratch spec. cproxy forwards `/api/*` generically, so
  the fronted docapi catalog is enumerated in `api-guide.html`, not here; but any change to cproxy's OWN
  surface (`/health`, `/health/ready`, `/metrics`, routing) goes in the Endpoints section.
- **`docs/postman-collection.json`** — a ready-to-import Postman collection covering every fronted
  endpoint plus cproxy's own `/health`/`/health/ready`/`/metrics`. Add/remove/adjust the request for
  the changed endpoint in the same change as the code, not after: it silently drifted once already,
  missing both `/news/featured` and `/news/more` for the several days between their addition (docapi
  1.8.1) and being caught here (2026-09-03). Follow the existing per-request shape — a `description`
  written for someone who has never seen the API, and the credential contract described under
  "Bearer token" in `api-guide.html` (an `Authorization: Bearer {{jwt}}` collection variable — the
  bare `X-Day-Guid` header was removed from the gateway in 0.13.0; it appears in the collection only
  in the "Credential contract" negative tests). **Since 2026-09-11 the collection covers every
  docapi route through the gateway (54 requests as of docapi 1.10.0, including the document CRUD, `/news/import`, both
  region PATCHes, and the PUT→405 cases) and every write ships with a body docapi rejects with 400,
  so the whole collection can be run against prod without writing data.** **The JSON is generated
  by `docs/gen-postman.py` — edit the generator and re-run it, never the JSON by hand** (a hand edit
  was lost to a regeneration once already). `docs/run-postman.py`
  executes it with no Postman/newman install (reads `jwt.txt`, checks each request's own expected
  status) — run it after any gateway deploy; 49/49 passed on 0.13.0.
  Gitignored (real IPs are fine here, same exception as `api-guide.html`), but still update it with
  the same discipline as a tracked file — nobody notices a stale Postman collection until it's the
  thing someone hands a new integrator.

**This rule fires even when nothing was touched to change the API.** A live-testing pass while
building or fixing either doc can surface that one of them was already wrong — a version number
copied from the other doc instead of the authoritative source (`pom.xml` for docapi's, `CHANGELOG.md`
for cproxy's own), an endpoint marked "not yet deployed" that shipped without anyone updating this
file, a documented example that no longer reproduces against current data. Found wrong is exactly as
much a trigger as changed: fix both docs in that same pass, not just the one you were originally
asked about. (User instruction, 2026-09-09, after exactly this happened: asked only to export
`postman-collection.json`, live-testing it surfaced three places `api-guide.html` was stale — two
endpoints marked undeployed that had shipped, and a stale example — plus a docapi version number
that turned out to be copied between the two docs rather than checked against `pom.xml` anywhere.)

Also update `README.md` (tracked — no real IPs) and this file's Changelog. The sibling `docapi` has the
same rule for its `docs/api-reference.html`.

---

## Git & deploy rules

- **DO NOT COMMIT / PUSH / open-merge-close PRs without explicit user permission** (repo `AGENTS.md`).
  Make edits and stop with a status summary unless Git actions are explicitly requested.
- Deploy target droplet `159.89.113.225`; SSH key in `efc-proxy/secret/proxy`; GHCR token in
  `efc-proxy/secret/ghcr.token`. **Never print secrets.** No deploy without explicit approval.
- **Repository:** `github.com/BalinTomsk/efc-proxy`. The service is committed on `main` and pushed
  (2026-08-04). In `service/cproxy/` **only `README.md` is tracked** — `AGENTS.md` and `docs/*` are
  gitignored local ops docs (so real IPs are fine here, never in the tracked README — see `AGENTS.md`
  → Documentation). The upstream it fronts, docapi's fish-search, is merged to `efj-backend` main
  (PR #85) and live as docapi 1.4.0.

---

## Project identity

| Key | Value |
|-----|-------|
| Service name | `cproxy` |
| Language | C++23 |
| Build | CMake ≥ 3.20 |
| HTTP engine | cpp-httplib (header-only), fetched via CMake FetchContent, pinned `v0.15.3` |
| Runtime | Debian 13 trixie-slim, single static-ish native binary |
| Container user | non-root uid 10001 |
| Listen port | 8080 (HTTP) |

---

## Layout

```
service/cproxy/
├── CMakeLists.txt          # C++23, FetchContent cpp-httplib, core lib + exe + ctest
├── Dockerfile              # multi-stage debian:trixie -> trixie-slim; runs ctest in-build
├── .dockerignore
├── .env.example
├── src/
│   ├── version.hpp.in      # -> generated/version.hpp (CPROXY_VERSION from PROJECT_VERSION)
│   ├── config.hpp/.cpp     # env-driven Config + pure load_config(EnvLookup) for testability
│   ├── secret_codec.hpp/.cpp # AES-256-GCM decrypt of enc:v1: values (OpenSSL; SecretCodec-compatible)
│   ├── dotenv.hpp/.cpp     # read .env, decrypt enc values, real-env-wins EnvLookup
│   ├── log.hpp/.cpp        # JSON console + daily-rolling file logger (waterservice parity)
│   ├── jwt_verifier.hpp/.cpp     # HS512-pinned compact-JWS verify (OpenSSL HMAC + nlohmann)
│   ├── clock_offset.hpp/.cpp     # in-process clock correction, moved only by an admin token
│   ├── user_prime_store.hpp/.cpp # `user` claim -> account, out of the RabbitMQ mirror's SQLite
│   ├── proxy.hpp/.cpp      # install_routes(): /health, prefix-forward, header filtering, 502
│   └── main.cpp            # load dotenv, load config, init logging, signals, listen
└── tests/
    └── config_test.cpp     # framework-free CTest over config parsing
```

`config` and `proxy` live in a `cproxy_core` static lib so `main` and the tests both link them; this
is what lets config parsing be unit-tested without spinning a server.

---

## Behaviour

- **`GET /health`** → `{"status":"UP","service":"cproxy","version":"<pom-equiv>"}`. Local, never
  forwarded. This is the HEALTHCHECK + liveness probe.
- **`<CPROXY_ROUTE_PREFIX>…`** (default `/api/`) → forwarded to `CPROXY_DOCAPI_UPSTREAM`. Preserves
  method, path+query (`forward_target` rebuilds it from `req.path` + `params`), headers, body. Strips
  hop-by-hop headers (RFC 7230 §6.1) + Host/Content-Length/Content-Type (the client/response set
  those). Adds `X-Forwarded-For/-Host/-Proto`.
- **Everything else** → 404.
- **Upstream down/slow** → `502 {"error":{"code":"bad_gateway",...}}`, honoring the connect/read
  timeouts. Every request logs one JSON line to stdout (`docker logs`).
- **Optional guards:** `CPROXY_API_KEY` → require `X-API-Key` (else 401); `CPROXY_ALLOWED_METHODS`
  CSV → reject others with 405. **POST/PATCH (and the `CPROXY_DAYKEY_PATHS` reads) additionally
  require the gateway credential** — `Authorization: Bearer <HS512 JWT>` whose `server` claim is the
  day-key (see "JWT credential" below) — orthogonal to both of the above, so a wrong/missing token
  answers 500, not 401. **Since 0.13.0 that token is the only credential; the raw `X-Day-Guid`
  header is not read anywhere in the code.**

### Datacenter / cloud-provider IP blocking (0.8.0)

The cproxy half of the frontend's `dbo.CloudProviderIpRange` control — read
`aspnet/Account/AGENTS.md` → "Anti-abuse: IP blocking" before touching either side, they are one
design in two services. A request from published datacenter space is refused **before every other
guard** with the same opaque `500` as a failed day-key.

`cloud_range_store.hpp/.cpp` holds the set; `cloud_range_refresh.hpp/.cpp` fetches the feeds. Table
`cloud_provider_ip_range(provider, cidr, ip_start, ip_end, disabled, source, updated_utc)` in its
own SQLite file (`CPROXY_CLOUDRANGE_DB`) — same shape and same filtered index as the frontend's.

Things that will bite you here:

- **Ranges are COALESCED at load, and that is not cosmetic.** The frontend's single-seek query
  (`TOP 1 … WHERE ipStart <= @n ORDER BY ipStart DESC`) is correct only while ranges are disjoint.
  Across twelve feeds they are not — one interval nested inside another makes that query answer
  "not blocked" for an address that *is* covered. Merging fixes it unconditionally; it also
  collapsed ~92k rows to under 4k intervals in the first live run, so any "why is the count so
  small?" is expected.
- **Never take the peer from `X-Forwarded-For`.** cproxy is the edge, so `req.remote_addr` is the
  real TCP peer and an inbound XFF is attacker-supplied. Honouring it makes the block both trivially
  bypassable and usable to get a third party blocked.
- **This store is fail-SAFE, the day-key store is fail-CLOSED.** A missing/corrupt range DB blocks
  nothing; a missing day-key DB 500s everything. Don't "make them consistent" — refusing all traffic
  because a data file went missing is the outage this arrangement exists to avoid. A file that is
  merely absent logs INFO (normal before the first refresh); a corrupt one logs ERROR.
- **`EXTERNAL_FRONTEND` / `EXTERNAL_ADMIN` are exempt automatically.** The portal's own host lives at
  a hosting provider whose space a feed can legitimately cover. Without that exemption the very
  first refresh could take the site offline. Keep it, and keep `CPROXY_BLOCK_CLOUD_IPS=false` as the
  no-redeploy rollback.
- **The refresher mirrors `envfish-db/mssql/tools/Update-CloudProviderRanges.ps1` feed for feed**,
  including both quirks that script documents (GCP entries with no `ipv4Prefix`; DigitalOcean's CSV
  served without a text content-type). Keep the ASN list in step with it. A failed feed keeps its
  own rows; if every feed fails the DB is untouched.
- **TLS is ON as of 0.8.0** (`HTTPLIB_USE_OPENSSL_IF_AVAILABLE`), reversing a deliberate earlier
  choice, purely because the provider feeds are HTTPS-only. The proxy path is unchanged and still
  plain HTTP to docapi. Consequences: libssl is a runtime dep, `ca-certificates` is load-bearing
  (without it every fetch fails cert verification), and the proxy now makes outbound internet calls.

### Logging (waterservice parity)

Same functionality as `waterservice`'s logback setup, hand-rolled in C++ (`log.hpp/.cpp`): structured
**JSON** lines to **both** the console (`docker logs`) and a **daily-rolling file**. The active file is
`<CPROXY_LOG_DIR>/cproxy.log`; at the first write of a new UTC day it rolls to
`cproxy.<YYYY-MM-DD>.log` and files older than `CPROXY_LOG_MAX_HISTORY` days (default 7) are pruned —
mirroring logback's `TimeBasedRollingPolicy` + `maxHistory`. One mutex serializes all writes so lines
never interleave across worker threads; each line is flushed (durable). **`CPROXY_LOG_DIR=NONE` →
console-only** — the sentinel, not `""`: an empty env var reads as *unset* (see "Config" below), so
`-e CPROXY_LOG_DIR=` falls back to the compiled-in default `logs` and keeps writing files. Request
lines are `{"ts","service":"cproxy","msg":"<method> <path> -> <status> (<ms>)"}`;
startup is one object with the effective config. Only proxied `/api/*` requests log a line (health/404
do not). The Docker image defaults `CPROXY_LOG_DIR=/var/log/cproxy` and pre-creates it owned by uid
10001; **in prod a DO volume is bind-mounted there** so logs persist across redeploys/reboots.

### Encrypted config (secret_codec + dotenv)

cproxy reads an optional dotenv file (`CPROXY_DOTENV_PATH`) and decrypts any `enc:v1:` value in it,
**byte-compatible with `secret/Protect-Env.ps1` and the Java `SecretCodec`** (docapi/waterservice):
AES-256-GCM, `enc:v1:base64url(nonce[12] ‖ ciphertext ‖ tag[16])`, **AAD = variable name**, 32-byte key
from `FF_MASTER_KEY_FILE` (hex/base64) — implemented with **OpenSSL libcrypto** (`secret_codec.cpp`).
`dotenv.cpp` parses the file, decrypts each marked value, and `make_env_lookup` layers it under the
real environment (a real env var always wins). A missing/wrong key on a present `enc:v1:` value is a
**fatal startup error** (`main` catches, logs FATAL, exits 1) — verified live. Values are read into
`Config.external_admin` / `Config.external_frontend` (`EXTERNAL_ADMIN` / `EXTERNAL_FRONTEND`) and are
**masked in logs** (only `set`/`unset` is recorded). Deploy: the encrypted `.env` and `master.key` live
on `volume-cnode` (`/mnt/volume_cnode/cproxy/`, uid 10001, `0400`), bind-mounted read-only into the
container; `secret/{.env,master.key,plaintext.env}` are gitignored, `secret/Protect-Env.ps1` is tracked.

### Day-key store (SQLite, `day_key_store.hpp/.cpp`)

**The credential for the write surface, plus any read explicitly listed** — the `server` claim of the
caller's Bearer JWT must match a per-day rotating credential, checked **in addition to** and
**independently of** `CPROXY_API_KEY`/`CPROXY_ALLOWED_METHODS`. Chosen deliberately over a single
static API key: a leaked/logged key stays valid forever, a leaked day-key is worthless the next day.
*(0.6.1–0.9.x read the GUID from a bare `X-Day-Guid` header; 0.10.0–0.12.0 accepted either; 0.13.0
removed the header path entirely — the day-key now reaches this store only from inside a verified
token. The paragraphs below still say "day-key gated" for the gate itself, because `DayKeyStore`,
`CPROXY_DAYKEY_DB` and `CPROXY_DAYKEY_PATHS` kept their names.)*

The gate has **two arms** (`Config::daykey_required`), and a request is gated if either matches:

- **By method, any path** — every `POST` and `PATCH` (today `PATCH /api/v1/river/fish/{guid}`,
  `PATCH /api/v1/river/description/{guid}`, `POST` on the regulation endpoints, and any future write
  docapi adds). Nothing to configure; a new write endpoint is covered the day it appears.
- **By document id, any method** — `CPROXY_DAYKEY_ID_PATHS` (default `/news`), new in **0.15.0**.
  Gates `<entry>/<guid>`, i.e. `GET /api/v1/news/{id}` — the article WITH its lead photo as
  base64 (~500 KB), which `News.aspx` calls on every article view. **This needed a new mechanism,
  not another CSV entry:** `CPROXY_DAYKEY_PATHS` is a path *tail* match and `/news/{id}` has no
  fixed last segment. Listing `/news` there would have worked via the `contains()` arm but would
  also have gated `/news/list` and `/news/search`, which are deliberately open — a page of JSON is
  cheap to assemble and is not what a scraper wants. The distinction is whether the request fetches
  **one document by id**. Only a canonical 8-4-4-4-12 hex GUID matches (`looks_like_document_id`),
  so no literal sibling route is swept in; a future templated route under a listed parent is gated
  automatically. **The two lists are independent switches** — an early return on an empty
  `daykey_paths` made `CPROXY_DAYKEY_PATHS=NONE` silently unguard `/news/{id}` in the first draft,
  and `the_two_path_gates_are_independent_switches` in `config_test` is what pins that.
- **By path, any method** — `CPROXY_DAYKEY_PATHS` (default `/news/default`, `/news/featured`,
  `/news/more`, `/news/photo`), the way a **read** is put behind the credential. Added in 0.7.0 for
  `GET /api/v1/news/default`: the assembled news home page is expensive for docapi to build and there
  is no reason to serve it to anonymous scrapers just because it happens to be a GET. **Every path
  that serves the same home-page content must be listed together** — 0.9.1 had to add
  `/news/featured` and `/news/more` days after docapi 1.8.1 split `/news/default` and left the
  expensive half open; 0.14.0 added `/news/photo` (docapi 1.9.0's raw-bytes form of the lead photos);
  0.15.0 added `/news/export` (the full interchange document, all three paragraph photos included —
  the largest response this gateway serves) and, via the separate `CPROXY_DAYKEY_ID_PATHS` shape
  rule, `GET /news/{id}`
  in the same release that created it, which is the pattern to keep. `PUT`/`DELETE` are deliberately *not* in the method arm — the
  `CPROXY_ALLOWED_METHODS` allow-list is what stops them, and adding them here would only change a
  405 into a 500.

Matching is on the **tail** of the path, so an entry works at any route prefix (`/news/default`
matches `/api/v1/news/default`); it is case-folded and trailing-slash-insensitive, and anything
*nested* under a gated path is gated too. The entry's leading `/` keeps it on a segment boundary, so
`/oldnews/default` does not match. **The dot-dot rejection deliberately runs before this gate** — a
tail match can't be stripped by traversal, but `/api/v1/news/default/../default` would otherwise
clear the gate and still normalize back to the gated endpoint at a Spring upstream.

**Turn the path arm off with `CPROXY_DAYKEY_PATHS=NONE`, not `""`** — `system_env` reports an empty
variable as unset, so an empty value silently leaves the default gate standing. (Same reason
`CPROXY_ALLOWED_METHODS` spells "no restriction" as `ALL`.)

- **Storage:** a read-only SQLite database, `day_keys(stamp TEXT PRIMARY KEY, guid TEXT NOT NULL)`,
  **one row per calendar date**. `DayKeyStore`'s constructor throws on an empty table, a malformed
  row (stamp not `YYYY-MM-DD`, or an empty guid), or the pre-0.9.0 schema — fail loud at startup,
  never silently accept or reject everything because the table came back in an unexpected shape.
  Location: `CPROXY_DAYKEY_DB` (empty/unset ⇒ every gated request always 500s, fails closed even if
  `CPROXY_ALLOWED_METHODS` permits the method). In prod this lives on `volume-cnode` in its **own**
  folder, sibling to the logs/`.env`/`master.key` mounts: `/mnt/volume_cnode/cproxy/daykeys/
  daykeys.sqlite`, bind-mounted read-only to `/etc/cproxy/daykeys.sqlite`, mode `0400` owned by
  uid 10001.
- **Keyed by DATE, not day-of-year (changed 0.9.0).** It used to hold exactly 365 rows indexed
  `1..365` and reuse them every year. That could not represent the generated key set: `daykeys.csv`
  and the `dbo.day_keys` MSSQL table are date-keyed and span ten years, so any 365-row projection of
  them agreed for about twelve months and then drifted — cproxy and every other consumer would have
  started disagreeing on 2027-09-02. Matching on the real date makes them agree by construction and
  **deleted two special cases**: the year-boundary wrap (365 → 1) and the leap-day clamp, where day
  366 reused day 365's key so 29 February and 31 December shared a credential. Real leap-day keys
  now exist. **The store is finite** — startup logs `day-key store loaded, days/from/to`, and past
  the last date every gated request fails closed with the usual opaque 500 and nothing else says
  why, so that log line is the only warning it is running out.
- **Generated out-of-band, never from source** — random v4 GUIDs, one per date, produced once and
  shipped as a binary SQLite file (same trust model as `master.key`: a secret artifact, not a build
  output). Rebuild it from `secret/daykeys.csv` (`stamp,guid`), which is the authoritative set and
  the same data as `secret/daykeys_mssql.sql`. **Never commit the key list or the `.sqlite` file** —
  `secret/` is gitignored. *(Watch out: `secret/daykeys_new.csv` is an earlier, superseded generation
  with different GUIDs — building from it produces a store that looks perfectly valid and rejects
  every live key.)*
- **Validation window:** `DayKeyStore::is_valid` accepts the key for **yesterday, today, or
  tomorrow** (UTC) rather than an exact match, so a request landing right at UTC midnight is never
  spuriously rejected. With real dates this is plain chrono arithmetic and an exact string lookup —
  no calendar special-casing at all.
- **Failure is a generic 500, never 401/403** — a wrong or missing day-key reads no differently to a
  prober than an ordinary server error, on purpose. It also means a malformed/missing SQLite file
  (load failure at startup, logged as `ERROR` but non-fatal to the process) degrades the gated
  requests to "always 500" without taking down the **ungated** GET surface, which loads
  independently. Note the blast radius grew in 0.7.0: a broken day-key file now also takes
  `/news/default` offline, not just the writes.
- **Loaded once at startup**, held in memory (an `unordered_map<date, guid>`; ten years is a few
  hundred KB), not
  re-queried per request; `ProxyState`'s constructor best-effort constructs it and swallows a load
  failure into a log line rather than crashing `install_routes`.
- Dependency: system `libsqlite3` via CMake's built-in `FindSQLite3` module (`SQLite::SQLite3`) —
  `libsqlite3-dev` at build time, `libsqlite3-0` at runtime (Dockerfile).

### JWT credential (0.10.0; the ONLY credential since 0.13.0 — `jwt_verifier.hpp/.cpp` + `user_prime_store.hpp/.cpp`)

**The day-key travels inside a signed token, never on its own in a header.** Callers present
`Authorization: Bearer <HS512 JWT>`; the frontend mints it in `aspnet/Account/FishApiJwt.cs`, and the
claim set is the one drawn in `fishfind-frontend/doc/envfish-jwt.html`:

```
{ "iss":"envfish", "iat":…, "exp":<end of the current UTC day>, "aud":"fishfind.info",
  "sub":"cproxy", "server":"<dbo.day_keys.guid for today>",
  "user":"<Users.prime * Users_Prime.prime for today>" }     ← `user` omitted when anonymous
```

**The token does not replace the rotation, it wraps it.** `server` is checked against `DayKeyStore`
exactly as the header was, so a leaked signing secret alone is worthless without today's GUID and a
harvested GUID is worthless without the secret. What the signature adds is that the credential is now
bound to an issuer, an audience, and an expiry — a copied request is no longer replayable from
anywhere for the rest of the day.

Things that will bite you here:

- **There is no second credential and no switch that restores one (0.13.0, 2026-09-11, at the
  user's request).** `check_gate_credential` reads only `Authorization: Bearer`. The `X-Day-Guid`
  fallback and `CPROXY_JWT_REQUIRED` (which decided whether that fallback was still honoured) were
  deleted, not defaulted off: a request carrying the bare header — even with today's correct key —
  logs `no bearer token presented` and gets the usual 500. A leftover `CPROXY_JWT_REQUIRED` in the
  environment is ignored with a startup WARN, so nobody mistakes `"false"` for a rollback. **An
  unset `CPROXY_JWT_SECRET` now shuts the gated surface** (every POST/PATCH and gated read 500s,
  startup logs an ERROR) instead of falling back to the header; the ungated reads keep serving, so
  it is deliberately not a fatal config error. The only way back to header auth is redeploying the
  0.12.0 digest. `proxy_test`'s `the_day_key_header_is_never_a_credential` is the guard — verified
  to fail if a header fallback is put back.
- **The `alg` header is pinned, never obeyed.** `verify_hs512` rejects anything that does not say
  HS512. Trusting the token's own `alg` is the classic forgery hole (`"alg":"none"` sails through;
  an RS256 verifier fed an HS256 token HMACs with the public key). Do not "generalise" this.
- **base64url must be canonical — the unused low bits of the last symbol must be zero** (unreleased
  as of 2026-09-11; not in the deployed 0.13.0 image). Until then `base64url_decode` discarded them,
  so an 86-char HS512 signature has 16 interchangeable last characters: a prod token ending `w`
  verified just as well ending `x`. No forgery (same MAC bytes), but a malleable token. The
  frontend's `Convert.ToBase64String` zero-fills, so its tokens are unaffected — the three golden
  fixtures in `jwt_verifier_test` prove it. **Padding (`=`) is still tolerated**, which is its own
  small malleability (appending `=` to a token still verifies); left alone because the tests pin it
  as deliberate — tighten it only as a decision, not a drive-by.
- **`exp` is mandatory.** A token without one would reintroduce exactly the "leaked credential is
  valid forever" property the day-key rotation exists to deny.
- **The `user` claim is a PRODUCT, compared as decimal text in 128-bit arithmetic.** Two bigint
  primes multiply past 2^63 well before the sequence runs out, and a wrapped `long` does not fail
  loudly — it silently authorises a different number. `UserPrimeStore` never does 64-bit
  multiplication; neither does the frontend (it uses `BigInteger`). If you touch either side, keep
  both.
- **`CPROXY_JWT_REQUIRE_USER` reads the RabbitMQ account mirror, which may be dormant.** Turning it
  on against an unpopulated mirror refuses every write and every signed-in visitor's reads — the
  store fails CLOSED, like the day-key store and unlike the cloud-range store. The startup line
  `user-prime store loaded, accounts` is there to be read *before* the switch is thrown. When on: a
  write must carry a `user` claim; a gated READ need not, because `/news/featured` and `/news/more`
  are the public home page and the gate there is against anonymous **scraping**, not anonymous
  **reading**. A claim that IS present is always checked.
- **`day_year` is 1..365 with no calendar attached**, so a date maps to day-of-year clamped to 365 —
  31 December of a leap year reuses day 365. `UserPrimeStore::day_of_year` and
  `FishApiJwt.TodaysDayYear` implement the same clamp; changing one without the other silently
  breaks one day a year.
- **Clock skew is ±`CPROXY_JWT_LEEWAY_SECONDS` (prod: 60), and an admin account can repair it
  (0.11.0; admin lookup 0.12.0).** A request with a MAC-verified token whose `user` product maps, in
  the account mirror, to a live `access = 255` account AND an `X-Client-Time` header moves
  `ClockOffset` when the two disagree by more than 5s, then re-verifies once. Five traps:
  - **Admin is looked up, never claimed.** 0.11.0 trusted an `"adm": true` claim; the user rejected
    it as insecure on 2026-09-11 (authority in whoever holds the signing secret; role readable by
    anyone decoding a token). `JwtClaims` now has no admin field, the frontend mints no role, and
    `UserPrimeStore::is_admin` reads `users_sync.access` — already delivered by the users-sync
    RabbitMQ stream, so no new column or event. **Do not add a role claim back**; if cproxy needs
    more about an account, mirror it. The portal decides admin by its `AdminUserIds` GUID list
    instead, and the two agree only while both admin accounts hold `access = 255`.
  - **`iat` is not the reference and must never become one.** `FishApiJwt` caches its token until
    UTC midnight and an admin downloads `jwt.txt` once a day, so `iat` is hours stale by design;
    aligning to it would drag cproxy backwards. The header carries the reading, the token carries
    the authority. If you ever "simplify" this by dropping the header, you reintroduce that bug.
  - **The offset never touches the system clock** — `cap_drop: ALL` forbids it, Docker shares the
    host kernel clock so it would move the whole droplet, and timesyncd would revert it. It reaches
    credential validation only; log timestamps stay real so they still match journald.
  - **`iss`/`aud`/`sub` are checked BEFORE `exp`/`iat`/`nbf`** so `time_rejected` can only be set on
    a token that is right about everything except the clock. Reordering those undoes the guarantee
    that a wrong-audience token cannot reach the alignment path.
  - **The ceiling clamps the TOTAL offset**, not the step — otherwise it is walkable by repetition.
- **The rollout (history, complete).** 0.10.0 shipped with `CPROXY_JWT_SECRET` empty ⇒ 0.9.x
  behaviour, then: frontend deploy → gateway secret → frontend `FishApi:JwtOnly=true` → gateway
  `CPROXY_JWT_REQUIRED=true` (2026-09-09) → 0.13.0 deleting the header path and the switch
  (2026-09-11). **The frontend's half of that is gone too as of 2026-09-11**: the `X-Day-Guid` send,
  the `FishApi:JwtOnly` property and its `Web.config` key were deleted when the gateway call moved
  into `aspnet/Models/FishApiClient.cs`. Both sides now know exactly one credential.
- **The secret is a dotenv value like any other**, so `CPROXY_JWT_SECRET=enc:v1:…` decrypts through
  `secret_codec` automatically. It must match `FishApi:JwtKey` in the frontend's `secrets.config`
  byte for byte. Use ≥ 64 random bytes; the signature is the only thing between a copied token and a
  forged one. (Live value: 64 bytes as 128 hex characters — hex rather than base64 so there is no
  `+` `/` `=` to survive an XML attribute, a dotenv line and a shell unscathed.)
- **NEVER regenerate `/mnt/volume_cnode/cproxy/.env` from `secret/plaintext.env` — it will delete
  live keys.** The droplet's dotenv carries `CPROXY_RABBITMQ_MANAGEMENT_URL` and
  `CPROXY_RABBITMQ_PASSWORD`, which are **not** in the local `plaintext.env`; they were added
  directly on the droplet. `Protect-Env.ps1` regenerates the whole file from the local source, so
  uploading its output silently drops both and turns the account mirror off — with only a
  `"RabbitMQ mirror disabled"` ERROR line to say so. `CPROXY_JWT_SECRET` was therefore **appended**
  to the droplet's own file (encrypted locally, `scp`'d as a one-line fragment, `cat >>`), never
  uploaded wholesale. Do the same for the next key, or reconcile `plaintext.env` with the droplet
  first. Backup before the append: `.env.bak-prejwt`.
- **The `add-fish` skill sends a token, and there is now exactly ONE copy of that skill:**
  `fishfind-frontend/.claude/skills/add-fish/SKILL.md`, with its gitignored `jwt.txt` / `proxy.url`
  beside it. **This directory used to hold two stale copies** (`docs/SKILL.md` and
  `docs/chat.skill`, ~90 lines behind and still sending `X-Day-Guid`); they were deleted 2026-09-09
  precisely because closing the gate turned them from merely stale into actively wrong. Do not
  reintroduce a copy here — link to the one in the frontend repo instead.
  The skill has **no credential fallback**: `jwt.txt` or it refuses to start. An admin downloads that
  file from **Profile → Gateway token** on the portal, which mints it with the same `FishApiJwt` the
  news path uses. That is the human-facing half of this design — the token is a *daily* credential
  expiring at 23:59:59 UTC, so it is a once-a-day download, exactly like the day-key it replaces.
  Postman sends only `Authorization: Bearer {{jwt}}` (collection-level auth) plus `X-Client-Time`.

### Caller role — `X-Fish-Role` (0.17.0)

cproxy tells docapi **who is asking**, in a header docapi trusts outright: `X-Fish-Role: guest | user | admin`,
set on **every** forwarded request. docapi uses it for `GET /news/list` — an admin gets the list ordered by
last edit, a registered user by article date, a guest by article date and never past row 100 — and cproxy is
the right place to say it, because cproxy is the one that verified the credential.

- **Derived from a verified token and the account mirror, never from the token's own claims.** `guest`
  unless the token verified (signature, expiry, and today's day-key in `server`) **and** its `user` product
  belongs to a live account in this service's mirror; `admin` when that account is a superAdmin
  (`users_sync.access == 255`), else `user`. There is still deliberately no admin *claim* (see 0.12.0).
- **It never blocks a request.** `/news/list` is an open path and stays one: a token is verified only when
  one is presented, and a missing, malformed, expired or wrongly-signed token is not an error there — it
  just means `guest`. On the gated surface the role is taken from the credential check that already ran.
- **Any inbound `X-Fish-Role` is dropped** (`is_unforwardable`), exactly like `X-Forwarded-*`, because
  httplib's `set_header` *appends* and docapi believes whatever it reads. Otherwise an anonymous
  `curl -H 'X-Fish-Role: admin'` would be a self-service admin. `proxy_test`
  `a_caller_supplied_role_header_is_never_forwarded` asserts there is exactly **one** copy upstream.
- **Fails closed to `guest`** with no JWT secret, no account mirror, an empty mirror, or an unknown
  product — docapi uses the role to *limit* what is shown, so "cannot tell" must read as the most
  restricted role.
- **The account mirror is now opened whenever a JWT secret is configured**, not only for
  `CPROXY_JWT_REQUIRE_USER` / `CPROXY_JWT_CLOCK_SYNC`, because the role is needed on every token-bearing
  request. With no secret nothing is verified and the mirror is never opened.
- **A guest's `/news/list` is capped by cproxy itself (0.17.1).** When the role is `guest` — no token, a token
  that does not verify, or a verified one whose `user` product is not a live account — the request forwarded
  to docapi has every `limit` and `offset` removed (however the key is spelled: docapi percent-decodes it, so
  `%6cimit=200` is caught too) and `offset=0&limit=100` appended; every other parameter (`country`, …) is
  forwarded as sent. So a guest is only ever given the first 100 rows of the list, whatever they ask for, and
  docapi is never even asked for more (its own cap is a second layer). A `user` or `admin` request is forwarded
  untouched, and only the news-list path is rewritten (`/news/search`, `/news/lake`, … are not). Tests:
  `a_guest_can_only_ask_for_the_first_hundred_rows`, `a_bad_or_anonymous_token_is_capped_like_no_token`,
  `a_registered_user_and_an_admin_are_not_capped`, `only_the_news_list_is_rewritten`.
- **Cost:** one SQLite-backed lookup per request that presents a token to an ungated path, cached for
  `CPROXY_JWT_USER_CACHE_SECONDS` like every other mirror read. Requests with no `Authorization` header
  (all anonymous browsing) do no extra work at all.

### Second upstream: waterapi (0.18.0 — DEPLOYED 2026-09-24)

**Live state:** image `0d7653901db2…4c72`. `CPROXY_WATERAPI_UPSTREAM=http://10.116.0.2:8090` was appended
to `/mnt/volume_cnode/cproxy/.env` (backups on the droplet: `.env.bak-prewater` and
`/opt/cproxy/compose.yml.bak-0.17.1`). Startup logs `"waterapi":"/api/v1/water/ -> http://…:8090"`.
The peering routes are installed by DigitalOcean's `vpc-peering.service` (enabled on both droplets), which
adds `10.0.0.0/8 via <own gw> dev eth1` at boot. On csnode it only did so after a reboot. cproxy still
has a hand-added `10.116.0.0/20 via 10.118.0.1` from before its next reboot. The route is removed by
deleting the dotenv line and running `compose up -d --force-recreate`.

`/api/v1/water/*` (`CPROXY_WATERAPI_PREFIX`) → `CPROXY_WATERAPI_UPSTREAM`. Unset upstream = no water
route (the prefix reaches docapi and 404s), so the image is safe to deploy before waterapi exists.

- **Own namespace, on purpose.** docapi already owns `/api/v1/station/{id}` (document CRUD), so waterapi
  lives under `/api/v1/water/` rather than borrowing docapi paths. waterapi's routes are
  `/api/v1/water/station/map` and `/api/v1/water/station/{sid}`.
- **Chosen from the decoded path, case-insensitively, AFTER the dot-dot rejection** (`select_upstream`).
  Every guard applies unchanged: datacenter block, methods, API key, traversal, credential gate,
  `X-Fish-Role` (inbound copy dropped), guest cap (news list only).
- **Own circuit breaker** (`ProxyState::water_breaker`). A waterapi outage must never fail-fast docapi.
  `/health/ready` still follows docapi only and reports `"waterapi":"<state>"` beside it; `/metrics`
  adds `cproxy_waterapi_breaker_state`. The pooled client is keyed per origin.
- **Two latent forwarding bugs surfaced by waterapi, both fixed in 0.18.0, both with tests that were
  run against the unfixed tree and failed:**
  1. **Compressed bodies were refused.** httplib here is built without zlib/brotli and, with
     decompression on (the default), fails the read of a `Content-Encoding: gzip|br` body → 502.
     `set_decompress(false)` now relays the bytes and header untouched. docapi never compresses, so it
     never showed; waterapi compresses whenever asked (US map 987 KB → 281 KB brotli).
  2. **A 304 took the whole read timeout.** httplib v0.15.3 skips the body only for 204. Kestrel's 304
     has no `Content-Length`, so the client read "until close": 10 s per ETag revalidation. A
     `response_handler` now stops at a 304's headers; the cancelled exchange is the complete answer.
     If httplib is ever upgraded past its own fix for this, the handler becomes redundant but harmless.
- **Verified 2026-09-23:** 10/10 ctest (+4 config, +6 proxy tests) in the Docker build stage. An
  end-to-end run of both real images on a private docker network in the Rancher VM (cproxy with docapi
  disabled → waterapi → production `vMapView`, read-only): 200 plain 987 KB, brotli 281 KB, 304 in
  2 ms (10013 ms before fix 2), sid lookup, 400 envelope, readiness showing both breakers.
- **Transport — DECIDED 2026-09-23: VPC peering (option a below).** Pending: the peering itself is a
  DigitalOcean control-panel action for the user. The local doctl token answers 403 on every VPC call,
  so it cannot be done from the workstation. After peering, prove `curl http://10.116.0.2:8090/health`
  from this droplet before enabling the route; DO may need a static route if it does not install one.
  Background: `debian-csnode` is on a **different VPC** (`eth1 10.116.0.2/20`) from
  cproxy (`10.118.0.0/20`), and cproxy has no route to it (checked 2026-09-23: `ip route` on cproxy shows
  only `10.118.0.0/20`). Options: (a) DigitalOcean **VPC peering** of the two VPCs (a control-panel
  action), then bind waterapi to `10.116.0.2:8090` and set `CPROXY_WATERAPI_UPSTREAM=http://10.116.0.2:8090`,
  keeping the private-path model docapi has; or (b) publish waterapi on csnode's public address, firewall
  `8090` to cproxy's public IP only, and set `CPROXY_WATERAPI_UPSTREAM=http://137.184.218.128:8090`
  (plain HTTP over the internet, read-only public map data). (a) is the recommended one.
- **Deploy:** append `CPROXY_WATERAPI_UPSTREAM` to `/mnt/volume_cnode/cproxy/.env` (append, NEVER
  regenerate — see the RabbitMQ warning above), then the usual build → push → pin digest → compose up.
  `compose.yml` must not carry the address (public repo, deployed verbatim). Steps: `docs/do-update.md`.

### Catch-all via pre_routing_handler

Routing is done in `Server::set_pre_routing_handler`, invoked for **every** method+path — the single
place to handle `/health`, forward the prefix, and let everything else fall through to 404. This is
why cproxy forwards all verbs uniformly without registering per-method routes.

---

## Config (all env; safe defaults)

`CPROXY_LISTEN_ADDR` (0.0.0.0) · `CPROXY_LISTEN_PORT` (8080) · `CPROXY_DOCAPI_UPSTREAM`
(`http://68.183.196.166:8080`) · `CPROXY_ROUTE_PREFIX` (`/api/`) · `CPROXY_WATERAPI_UPSTREAM` (empty ⇒
no water route) · `CPROXY_WATERAPI_PREFIX` (`/api/v1/water/`; must be strictly inside the route
prefix) · `CPROXY_API_KEY` (none) ·
`CPROXY_ALLOWED_METHODS` (all) · `CPROXY_DAYKEY_DB` (empty ⇒ every gated request always 500s) ·
`CPROXY_DAYKEY_PATHS` (`/news/default,/news/featured,/news/more,/news/photo`; CSV of paths
day-key gated on every method, `NONE` disables) ·
`CPROXY_JWT_SECRET` (empty ⇒ every gated request 500s — there is no other credential) ·
`CPROXY_JWT_REQUIRE_USER` (`false`; prod `true`) · *(`CPROXY_JWT_REQUIRED` was removed in 0.13.0 —
ignored with a WARN)* · `CPROXY_JWT_ISSUER` (`envfish`) ·
`CPROXY_JWT_AUDIENCE` (`fishfind.info`) · `CPROXY_JWT_SUBJECT` (`cproxy`; all three take `NONE` to
skip that claim) · `CPROXY_JWT_LEEWAY_SECONDS` (300 — **prod sets 60**) ·
`CPROXY_JWT_USER_CACHE_SECONDS` (60) · `CPROXY_JWT_CLOCK_SYNC` (`true`) ·
`CPROXY_JWT_CLOCK_SYNC_THRESHOLD_SECONDS` (5) · `CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS` (3600) ·
`CPROXY_CLOUDRANGE_DB` (empty ⇒ datacenter blocking off) · `CPROXY_BLOCK_CLOUD_IPS` (`true`;
kill-switch) · `CPROXY_CLOUDRANGE_REFRESH_HOURS` (336, fortnightly) ·
`CPROXY_CLOUDRANGE_REFRESH_ON_START` (`false`) · `CPROXY_CLOUDRANGE_FETCH_TIMEOUT_SECONDS` (60) ·
`CPROXY_CLOUDRANGE_PROVIDERS` (all 12; `NONE` stops refreshing, keeps blocking) ·
`CPROXY_CLOUDRANGE_EXEMPT_IPS` (admin/frontend exempt automatically) ·
`CPROXY_CONNECT_TIMEOUT_MS` (3000) · `CPROXY_READ_TIMEOUT_MS`
(10000) · `CPROXY_LOG_DIR` (`logs`; image sets `/var/log/cproxy`; `NONE` = console-only) ·
`CPROXY_LOG_MAX_HISTORY` (7). `load_config(EnvLookup)` is pure; `system_env` wraps getenv and treats
an **empty string as unset — with no exceptions**. Malformed ints fall back to the default rather
than crash.

**Corollary, and the reason every off switch is a word:** no variable can carry "explicitly empty" as
a distinct state through a real process environment, so `""` can only ever mean "use the default".
Anything that needs an *off* value spells it out — `CPROXY_ALLOWED_METHODS=ALL`,
`CPROXY_DAYKEY_PATHS=NONE`, `CPROXY_LOG_DIR=NONE`. Two of those were written as `""` first and were
silent no-ops in production while their unit tests passed, because the test fake hands back a genuine
empty string that `getenv` never produces. **Any new switch must be asserted through `system_env` and
the real environment** (`put_real_env` in `config_test`), never through `make_env` alone. Note that
`make_env_lookup` (the dotenv layer) *can* yield a real empty string, so a dotenv line may behave
differently from `-e` — one more reason not to give `""` a meaning.

---

## Build / test / Docker

- Local: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel && ctest --test-dir build`.
- Docker: multi-stage; `cmake build` + `ctest` run in the **build** stage so a broken build never
  ships. cpp-httplib TLS/zlib/brotli integrations are turned **OFF** (lean binary; cproxy speaks HTTP
  to internal upstreams — public TLS termination is a fronting concern, not this process's).
- **Base images:** referenced by tag (`debian:trixie` / `trixie-slim`); pin by digest for release
  reproducibility (matches the sibling services' convention).

---

## Reachability (WIRED 2026-08-04 — DigitalOcean VPC)

Both droplets sit in the same DigitalOcean VPC on `eth1` (`10.118.0.0/20`): docapi = `10.118.0.3`,
cproxy = `10.118.0.2`. docapi is published on **both** `127.0.0.1:8080` (its own health checks) **and**
`10.118.0.3:8080` (the VPC), so cproxy reaches it privately at `http://10.118.0.3:8080` — that is
`CPROXY_DOCAPI_UPSTREAM` in prod. This is a **private** path: docapi is **not** bound to `0.0.0.0`, so
it stays off the public internet (verified: `http://68.183.196.166:8080` refuses). The dual-bind is
baked into the `update-docapi` skill (Step 9 `-p 10.118.0.3:8080:8080`) so future docapi deploys keep
it — **do not drop that bind or cproxy's `/api/*` breaks.**

---

## Deployment (prod)

- **Droplet:** `159.89.113.225` (Debian 13 trixie, Docker 29.7.1). SSH key `efc-proxy/secret/proxy`.
- **Image:** `ghcr.io/balintomsk/cproxy:0.13.0` (token `efc-proxy/secret/ghcr.token`). Live digest is
  pinned in `compose.yml` — currently `sha256:fa491894…25af` (2026-09-11).
- **Persistent volume `volume-cnode`:** DO block volume, already ext4-formatted + mounted at
  `/mnt/volume_cnode` (in `/etc/fstab` with `nofail` for reboot persistence). Under
  `/mnt/volume_cnode/cproxy/` (all uid 10001): `logs/` (→ container `/var/log/cproxy`), the encrypted
  `.env` and `master.key` (`0400`, → container `/etc/cproxy/*` read-only). **Do NOT run `mkfs` on the
  volume — it is already formatted and holds data.**
- **Run:** managed by **`docker compose -f /opt/cproxy/compose.yml up -d --pull always`** (not a raw
  `docker run` any more). The run config's source of truth is `service/cproxy/deploy/compose.yml` in git
  (image **pinned by DIGEST**, hardened: `read_only`, `cap_drop: ALL`, `no-new-privileges`, uid 10001);
  the droplet copy lives at `/opt/cproxy/compose.yml`. The full build→push→pin→deploy procedure is
  `docs/do-update.md`. **The public port is firewalled to an allowlist** (`DOCKER-USER` iptables via
  `cproxy-firewall.service`), so verification must run from an allowlisted host.
- **Rotate secrets:** edit `secret/plaintext.env`, run `secret/Protect-Env.ps1`, then copy `.env`
  (and `master.key` if the key changed) to `/mnt/volume_cnode/cproxy/` (`chown 10001:10001`, `chmod
  0400`) and restart the container. The container crash-loops if an `enc:v1:` value can't be decrypted.
- **Public edge:** `http://159.89.113.225/` (port 80). `GET /api/*` → docapi; `GET /health` → local.
  **As of 0.6.1 (2026-08-25): `GET` and `PATCH` are allowed** — every other method still 405s. There
  is still **no `CPROXY_API_KEY`** (so the frontend needs no changes), but **every POST/PATCH
  additionally requires the gateway credential** — a Bearer JWT carrying the day-key (see "JWT
  credential" above; the bare `X-Day-Guid` header of 0.6.1–0.9.x is gone as of 0.13.0) — a
  wrong/missing one is `500`, not `401`. **The same credential gates four GETs,
  `/api/v1/news/default|featured|more|photo/{id}`** (`CPROXY_DAYKEY_PATHS`); every other read stays
  open. To further lock down GET too: add
  `-e CPROXY_API_KEY=<secret>` and have the caller send `X-API-Key`.
- No reverse-proxy skill yet — redeploy by re-running the above with a new tag (build+push from the
  Rancher VM like docapi). **Keep the `-v …:/var/log/cproxy` mount** or logs won't persist.

## Verified

- **Prod (2026-09-11, cproxy 0.13.0 — header path removed):** digest `sha256:fa491894…25af`,
  `/health` → `0.13.0`, startup `"jwt":"on (bearer only, user claim enforced)"`,
  `user-prime store loaded, accounts 9, admins 6`, no WARN/ERROR. A 49-probe sweep of **every**
  fronted route and guard (scratch script, run before the deploy against 0.12.0 and after against
  0.13.0) came back **identical** on status and responder, and the regenerated Postman collection
  ran 49/49 through `docs/run-postman.py`: all reads 200 through to docapi, every
  write clears the gate and reaches docapi (a 400 on a deliberately invalid body — nothing written),
  PUT/DELETE 405 at the gateway, traversal 400, no-route 404. Credential contract: bare `X-Day-Guid`
  **with today's correct key** → 500 on a gated read and on a PATCH, logged `no bearer token
  presented`; `Authorization: Basic` → same; a bit-flipped signature → `signature mismatch`.
  Pre-existing and unrelated, seen in both sweeps: `GET /fish|waterbody|station/{id}` answer
  docapi's own `500 internal_error`, and `GET /fish?water=fresh` is `400` (docapi 1.8.3 has no
  `water` parameter; the old Postman entry for it was wrong).
- **Prod (2026-09-08, cproxy 0.10.0 — the JWT credential):** `/health` → `0.10.0`; startup line
  `"jwt":"on (X-Day-Guid still accepted, user claim ignored)"` (which is also how you know the
  encrypted `CPROXY_JWT_SECRET` decrypted). Gate exercised from the allowlisted workstation with a
  token minted by the deployed `FishTracker.dll`: **no creds → `500 (day-key check failed)`**,
  **valid Bearer JWT → cleared the gate**, **valid `X-Day-Guid` → cleared the gate**, **tampered
  token → `500 (jwt rejected: signature mismatch)`**. `/river/unfished`, `/fish/search`,
  `/news/list` all `200` on the token, so the add-fish surface works.
  **Distinguish the two 500s by BODY, not status** — cproxy's refusal is `{"error":…}` with no
  `data`/`meta`; the valid credentials got docapi's `{"data":null,…,"meta":…}`, i.e. they reached
  the upstream. `/news/default|featured|more` are **failing inside docapi**, pre-existing and
  unrelated: the untouched day-key path fails identically and every other endpoint is fine.
  `CPROXY_JWT_REQUIRED` / `CPROXY_JWT_REQUIRE_USER` both still **off** at this point — rollout step
  2 of 4.
- **Prod (2026-09-09, `CPROXY_JWT_REQUIRED=true` — rollout COMPLETE):** frontend `FishApi:JwtOnly`
  flipped first, then this. Startup reads `"jwt":"on (required, user claim ignored)"`. Re-verified on
  the next UTC day's key (day_year 252, so the daily rollover was exercised): **`X-Day-Guid` alone
  now answers cproxy's own `500` on both a gated GET and a PATCH**, a Bearer token clears both
  (`PATCH /river/fish/{all-zero-guid}` with `[]` reaches docapi and gets its `400 invalid_document`
  — the gate runs before anything is forwarded, so that proves the write surface without touching a
  row), and the ungated GET surface is untouched. `CPROXY_JWT_REQUIRE_USER` was still **off** here.
- **Prod (2026-09-09, `CPROXY_JWT_REQUIRE_USER=true`):** turned on once the account mirror was
  populated by `envfish-db`'s `sp_user_prime_sync_backfill`. Startup reads
  `"jwt":"on (required, user claim enforced)"` and
  `"msg":"user-prime store loaded","accounts":9,"error":""` — 3 accounts × the 3-day window, and an
  empty `error`, which is also the proof that the READ-ONLY open of the **WAL** mirror works from
  inside the container (a read-only open of a WAL database is the thing most likely to fail here).
  Verified on prod: a write with a valid claim clears the gate (docapi `400 invalid_document`); a
  write with **no** claim logs `jwt carries no user claim on a write`; a **bogus** claim logs
  `jwt user claim does not match a live account` on both a write and a gated read; a gated read with
  **no** claim is still served (anonymous reads deliberately preserved); the ungated surface is
  untouched. The add-fish skill runs unchanged against it.

- **Local (2026-08-04):** image built (C++23, cpp-httplib v0.15.3, `config_test` 1/1); `/health` 200;
  404; 502 on unreachable upstream; end-to-end via `traefik/whoami` (path+query + `X-Forwarded-*`);
  API-key 401/200; GET-only 405 on POST.
- **Prod (2026-08-04):** `http://159.89.113.225/health` → 200 from the public internet;
  `http://159.89.113.225/api/v1/fish/search?q=trout` → real ranked docapi data over the VPC; public
  `POST /api/*` → 405 (GET-only); docapi confirmed NOT public (`68.183.196.166:8080` refuses).
- **Prod (2026-08-25, cproxy 0.6.1):** `/health` → `0.6.1`; `PATCH /api/v1/river/fish/{guid}` with no
  `X-Day-Guid` → `500`, a wrong one → `500`, **the correct day's key → `200`** with a real
  insert/GET-confirmed/cleaned-up round trip through the full stack (gateway → docapi →
  `sp_lake_fish_upsert_batch` → prod DB); other write verbs (`POST`, `PUT`) still `405`; GET
  endpoints, the traversal guard (`400`), and the no-route case (`404`) unchanged. Found and fixed a
  real bug live during this deploy — see the 0.6.1 changelog entry for the Content-Type-forwarding
  fix.

---

## Changelog

Moved to [`CHANGELOG.md`](./CHANGELOG.md) (same directory, also gitignored/local-only) for
readability — this file was getting long. Newest entries first there.
