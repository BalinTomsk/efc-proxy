# cproxy — specification

Single source of truth for recreating the `cproxy` service from scratch. Keep it in sync with the
code: every change is ① edit code, ② update this file (and `CLAUDE.md` when behaviour/structure/config
changes).

> **Addresses here are placeholders.** This repo is public, so every real host is written as
> `<cproxy-droplet>`, `<docapi-droplet>`, `<second-droplet>`, `<docapi-vpc>`, `<vpc-cidr>`.
> The real values live in the gitignored `CLAUDE.md` → Deployment/Reachability and in `secret/`.
> Never paste a real address into this file. `127.0.0.1` and `0.0.0.0` are literal.

## Purpose

A C++23 reverse proxy that is the edge between the ASP.NET frontend `fishfind.info` and the internal
backend droplets. Runs in Docker on Debian 13 ("trixie") on droplet **<cproxy-droplet>**. Gives the
frontend one REST entry point and forwards inward.

- **Now:** fronts `docapi` (droplet `<docapi-droplet>`) for `fishfind.info`.
- **Planned:** additional upstream on droplet `<second-droplet>` via a new route.

```
fishfind.info ──HTTP──►  cproxy :8080  ──HTTP──►  docapi :8080
                          /api/*  → docapi
                          /health → local (never forwarded)
                          other   → 404
```

## Endpoints

| Verb | Path | Behaviour |
|------|------|-----------|
| `GET` | `/health` | `200 {"status":"UP","service":"cproxy","version":"<ver>"}` — local liveness (always 200, even during an upstream outage) |
| `GET` | `/health/ready` | readiness — `200 {…,"upstream":"closed"}` when the circuit breaker is closed, `503 {…,"upstream":"open"}` when it is open (0.5.0) |
| `GET` | `/metrics` | Prometheus text: requests by status, upstream latency, failures, retries, short-circuits, breaker state (0.5.0) |
| any | `<route_prefix>…` (default `/api/`) | reverse-proxied to `CPROXY_DOCAPI_UPSTREAM`. The **fronted docapi catalog** (fish / news / river / … endpoints reachable through the gateway) is enumerated for callers in `docs/api-guide.html` — keep that guide in sync when a fronted endpoint is added/changed. |
| any | anything else | `404 {"error":{"code":"not_found",...}}` |

### Forwarding contract

- Preserves: HTTP method, **path + query string**, request body.
- Headers: forwards all request headers **except** hop-by-hop (RFC 7230 §6.1: connection, keep-alive,
  proxy-authenticate, proxy-authorization, te, trailer, transfer-encoding, upgrade) and
  host/content-length/content-type (set by the client/response layer). Adds `X-Forwarded-For` (client
  IP), `X-Forwarded-Host`, `X-Forwarded-Proto: http`.
- Response: copies upstream status, body, and non-hop-by-hop headers; content-type carried through.
- **Failure mapping:** unreachable/timed-out upstream → `502 {"error":{"code":"bad_gateway",...}}`,
  honoring `CPROXY_CONNECT_TIMEOUT_MS` / `CPROXY_READ_TIMEOUT_MS`.
- **Optional guards:** if `CPROXY_API_KEY` is set, a request lacking a matching `X-API-Key` → `401`;
  if `CPROXY_ALLOWED_METHODS` is a non-empty CSV, a method not in it → `405`.
- **Day-key guard:** independent of the two guards above — a gated request additionally requires the
  current UTC date's credential from the `CPROXY_DAYKEY_DB` SQLite database, presented since 0.10.0
  as the `server` claim of an `Authorization: Bearer <HS512 JWT>` (see "JWT credential" below) or, in
  the pre-0.10.0 form still accepted until `CPROXY_JWT_REQUIRED` is on, in the header `X-Day-Guid`
  matching that same value from the `CPROXY_DAYKEY_DB` SQLite database
  (`day_keys(stamp TEXT PRIMARY KEY, guid TEXT NOT NULL)`, one row per calendar date; ±1 day window);
  a wrong or missing value → `500` (deliberately not `401`, so it reads no
  differently from an ordinary server error). Two arms, either one gates: **every POST/PATCH**
  whatever the path, and **every method on a path in `CPROXY_DAYKEY_PATHS`** (default
  `/news/default`, `/news/featured` and `/news/more` — this is how a *read* is put behind the
  credential, added 0.7.0; the two extra entries came in 0.9.1 when docapi 1.8.1 split the home
  page and left them as an unauthenticated bypass). Matching is on
  the path tail, case-folded, trailing-slash-insensitive, and covers anything nested under a gated
  path; dot-dot is rejected before the gate so traversal cannot re-point a request past it. See
  `DayKeyStore` below.

## Configuration (environment only)

| Variable | Default | Meaning |
|----------|---------|---------|
| `CPROXY_LISTEN_ADDR` | `0.0.0.0` | bind address |
| `CPROXY_LISTEN_PORT` | `8080` | bind port |
| `CPROXY_DOCAPI_UPSTREAM` | `http://127.0.0.1:8080` | docapi origin. The default is a neutral local placeholder; prod sets the VPC address (`http://<docapi-vpc>:8080`) explicitly |
| `CPROXY_ROUTE_PREFIX` | `/api/` | forwarded path prefix |
| `CPROXY_API_KEY` | (empty) | require `X-API-Key` when set |
| `CPROXY_ALLOWED_METHODS` | (empty = all) | CSV method allow-list |
| `CPROXY_DAYKEY_DB` | (empty) | path to the day-key SQLite db; empty ⇒ every gated request always `500` |
| `CPROXY_DAYKEY_PATHS` | `/news/default,/news/featured,/news/more` | CSV of paths day-key gated on **every** method, GET included; `NONE` disables (an empty value reads as unset) |
| `CPROXY_JWT_SECRET` | (empty) | HS512 shared secret; empty ⇒ Bearer tokens are not verified and only `X-Day-Guid` is accepted |
| `CPROXY_JWT_REQUIRED` | `false` | `true` ⇒ a valid token is the only accepted credential |
| `CPROXY_JWT_REQUIRE_USER` | `false` | `true` ⇒ writes must carry a `user` claim; any claim present must match a live account |
| `CPROXY_JWT_ISSUER` / `_AUDIENCE` / `_SUBJECT` | `envfish` / `fishfind.info` / `cproxy` | required claims; `NONE` skips one |
| `CPROXY_JWT_LEEWAY_SECONDS` | `300` | clock-skew allowance on `exp`/`iat` |
| `CPROXY_JWT_USER_CACHE_SECONDS` | `60` | account-prime snapshot lifetime (also the revocation lag) |
| `CPROXY_CLOUDRANGE_DB` | (empty) | SQLite datacenter-IP range db; empty ⇒ feature off entirely |
| `CPROXY_BLOCK_CLOUD_IPS` | `true` | kill-switch; `false` keeps data + refresh but refuses nothing |
| `CPROXY_CLOUDRANGE_REFRESH_HOURS` | `336` | fortnightly provider-feed refresh |
| `CPROXY_CLOUDRANGE_REFRESH_ON_START` | `false` | fetch at boot instead of waiting an interval |
| `CPROXY_CLOUDRANGE_FETCH_TIMEOUT_SECONDS` | `60` | per-feed HTTP timeout |
| `CPROXY_CLOUDRANGE_PROVIDERS` | (all 12) | CSV of feeds; `NONE` stops refreshing, keeps blocking |
| `CPROXY_CLOUDRANGE_EXEMPT_IPS` | (empty) | never blocked (admin + frontend exempt automatically) |
| `CPROXY_CONNECT_TIMEOUT_MS` | `3000` | upstream connect timeout |
| `CPROXY_READ_TIMEOUT_MS` | `10000` | upstream read timeout |
| `CPROXY_LOG_DIR` | `logs` (Docker image: `/var/log/cproxy`) | rolling-log directory; `NONE` = console-only (an empty value reads as unset) |
| `CPROXY_LOG_MAX_HISTORY` | `7` | days of rolled log files to keep |

`load_config(EnvLookup)` is a pure function (env lookup injected) so it is unit-testable; `system_env`
is the process-backed default and treats an empty string as unset. A malformed integer falls back to
its default instead of failing startup.

**Empty is never a meaningful value.** `system_env` collapses `getenv() == ""` to `nullopt`, so
through a real process environment `-e VAR=` is indistinguishable from not setting `VAR` at all and
can only mean "use the default". Every switch therefore spells its *off* state as a word —
`CPROXY_ALLOWED_METHODS=ALL`, `CPROXY_DAYKEY_PATHS=NONE`, `CPROXY_LOG_DIR=NONE` (all case-insensitive
and trimmed). Two of these were originally specified as `""` and were silent no-ops in production
while their unit tests passed, because the injected test `EnvLookup` returns a genuine empty string
that `getenv` never produces; `config_test` now pins the contract through `system_env` and the real
process environment (`put_real_env`) so the two cannot drift again. The dotenv layer
(`make_env_lookup`) *can* return a real empty string, which is a further reason no rule depends on
one.

## Code structure

```
src/
  version.hpp.in       configure_file -> generated/version.hpp; CPROXY_VERSION = project VERSION
  config.hpp/.cpp      Config struct + load_config(EnvLookup); method_allowed(); auth_required();
                       daykey_required(method,path) / daykey_gated_path(path)
  log.hpp/.cpp         JSON console + daily-rolling-file logger; init_logging/log_line/log_raw
  day_key_store.hpp/.cpp  SQLite-backed per-DATE rotating credential; DayKeyStore::is_valid()
  jwt_verifier.hpp/.cpp   HS512-pinned compact-JWS verify; verify_hs512(), bearer_token()
  user_prime_store.hpp/.cpp  `user` claim -> account, from the account mirror; UserPrimeStore::is_valid()
  proxy.hpp/.cpp       install_routes(Server&, Config&): per-method routes; forwarding; gate credential
  main.cpp             load config; init logging; SIGINT/SIGTERM -> server.stop(); listen
tests/
  config_test.cpp          framework-free assertions; registered with CTest
  day_key_store_test.cpp   yesterday/today/tomorrow window, year boundary, leap-day-366 clamp
  jwt_verifier_test.cpp    forged/tampered tokens, alg:none, HS256 downgrade, expiry, claim checks
  user_prime_store_test.cpp  prime product incl. past 2^63, revoked accounts, day window, fail-closed
  proxy_test.cpp           real HTTP through install_routes(); includes the gated-read cases
                           (/news/default, /news/featured, /news/more all 500 without a key,
                            502 through with one, siblings open) and the JWT gate end to end
```

## Day-key store (0.9.0: date-keyed)

`day_key_store.hpp/.cpp`. A read-only SQLite table `day_keys(stamp TEXT PRIMARY KEY, guid TEXT NOT
NULL)`, one row per calendar date, loaded once at startup into an `unordered_map<date, guid>` and
never re-queried per request. `is_valid(guid, now)` accepts yesterday / today / tomorrow in UTC.

- **Why date-keyed.** Until 0.9.0 the table was `day_keys(day_of_year INTEGER, guid)` with *exactly*
  365 rows, reused every year. The generated key set (`secret/daykeys.csv`, and the `dbo.day_keys`
  MSSQL table) is date-keyed and spans ten years, so any 365-row projection of it agreed for roughly
  twelve months and then drifted — the consumers would have started disagreeing on 2027-09-02.
  Matching the real date makes them agree by construction.
- **Two special cases disappeared with it:** the year-boundary wrap (day 365 → 1) and the leap-day
  clamp, where day 366 reused day 365's key so 29 February and 31 December shared a credential.
  29 February is now an ordinary distinct key.
- **Fails loud at startup** on an empty table, a malformed row (stamp not `YYYY-MM-DD`, empty guid),
  or the pre-0.9.0 day-of-year schema — the last matters because a new binary against an old
  database would otherwise load nothing and silently 500 the entire gated surface.
  `day_key_store_test.legacy_day_of_year_schema_throws` pins it.
- **The store is finite.** Startup logs `day-key store loaded` with `days` / `from` / `to`; past the
  last date every gated request fails closed with the usual opaque `500` and nothing else explains
  why, so that line is the only warning it is expiring.
- **Deploying a new store is a two-part change**: binary and SQLite must land together, since each
  version rejects the other's schema. Upload the file next to the *running* container (which holds
  its keys in memory and is unaffected), then recreate once.

## JWT credential (0.10.0)

`jwt_verifier.hpp/.cpp` + `user_prime_store.hpp/.cpp`. The day-key now travels inside a signed token
rather than on its own in a header. Callers send `Authorization: Bearer <HS512 JWT>`, minted by the
frontend (`aspnet/Account/FishApiJwt.cs`):

```json
{ "iss": "envfish", "iat": 1788880000, "exp": 1788911999, "aud": "fishfind.info",
  "sub": "cproxy", "server": "<today's day-key GUID>", "user": "<Users.prime * Users_Prime.prime>" }
```

- **The token wraps the rotation, it does not replace it.** `server` is checked against `DayKeyStore`
  exactly as `X-Day-Guid` was. A leaked signing secret alone is worthless without today's GUID, and a
  harvested GUID is worthless without the secret; both are required. What the signature adds is that
  the credential is bound to an issuer, an audience and an expiry, so a copied request is no longer
  replayable from anywhere for the rest of the day.
- **HS512 is pinned; the token's own `alg` is never obeyed.** Trusting it is the classic forgery hole
  (`"alg":"none"`; an RS256 verifier HMACing with a public key). `exp` is mandatory — an unbounded
  token would reintroduce the property the rotation exists to deny. The MAC is compared with
  `CRYPTO_memcmp` before any claim is read.
- **A present-but-invalid token is fatal even while `CPROXY_JWT_REQUIRED` is off.** The header
  fallback exists for callers that send *no* token; falling back on a failed one would allow a
  downgrade past the signature with a day-key harvested from anywhere.
- **`user` is a product of two primes, compared as decimal TEXT in 128-bit arithmetic.**
  `UserPrimeStore` re-derives `users_sync.prime × user_prime_sync.prime` for the day from cproxy's own
  account mirror (never MSSQL) and matches strings. The two bigints multiply past 2^63, and a wrapped
  64-bit product would not fail loudly — it would authorise a different number. Suspended, deleted,
  unallocated (`prime = 0`) and prime-expired accounts do not match. `day_year` is 1..365 with no
  calendar attached, so a date maps to day-of-year clamped to 365 (31 December of a leap year reuses
  day 365) — the frontend applies the identical clamp.
- **The snapshot is rebuilt every `CPROXY_JWT_USER_CACHE_SECONDS`**, which is also how long a
  revocation takes to bite. A missing or unreadable mirror installs an *empty* set: fail-closed, like
  the day-key store and unlike the cloud-range store.
- **`CPROXY_JWT_REQUIRE_USER` demands a `user` claim on writes only.** A gated *read* may still be
  anonymous — `/news/featured` and `/news/more` are the public home page, and the gate there is
  against anonymous scraping, not anonymous reading. A claim that *is* present is checked either way.
- **Failure is the same opaque `500`** as a failed day-key. The reason goes to the log only.
- **Rollout, three reversible switches:** `CPROXY_JWT_SECRET` empty ⇒ 0.9.x behaviour exactly →
  set the secret (both credentials accepted) → frontend `FishApi:JwtOnly=true` → gateway
  `CPROXY_JWT_REQUIRED=true`. Until the last step nothing has been taken away from someone holding
  the day-key.

## Datacenter / cloud-provider IP blocking (0.8.0)

The cproxy half of the frontend's `dbo.CloudProviderIpRange` control (`aspnet/Account/CLAUDE.md`).
A request whose peer address falls in published datacenter space is refused **before every other
guard** with the same opaque `500` as a failed day-key.

- **Store** (`cloud_range_store.hpp/.cpp`). SQLite table `cloud_provider_ip_range(provider, cidr,
  ip_start, ip_end, disabled, source, updated_utc)`, PK `(provider, cidr)`, partial index on
  `ip_start WHERE disabled = 0` — the same shape and the same filtered index as the frontend's
  table, so the two remain recognisably one design.
- **Lookup is in-memory, not per-request SQL.** cproxy sees every call, so enabled rows are loaded
  once into a sorted vector and binary-searched. Refreshes publish a new snapshot through
  `std::atomic<std::shared_ptr<const vector>>`, so readers never lock and never see a partial set.
- **Ranges are coalesced at load.** The frontend's `TOP 1 … ORDER BY ipStart DESC` seek is correct
  only for *disjoint* ranges; a nested interval would make it answer "not blocked" for a covered
  address. Merging overlapping and adjacent windows makes the search correct unconditionally. In
  practice it also collapses ~92k published rows to under 4k intervals.
- **Peer address is `req.remote_addr`, never `X-Forwarded-For`.** cproxy is the edge; an inbound
  XFF is attacker-controlled, so honouring it would make the block both bypassable and abusable.
- **Fail-safe, not fail-closed** (the opposite of the day-key store): a missing or unreadable
  database leaves the set empty and blocks nothing. A missing file logs at INFO — that is the
  normal state before the first refresh — while a corrupt one logs ERROR.
- **Escape hatches:** `CPROXY_BLOCK_CLOUD_IPS=false`; `CPROXY_CLOUDRANGE_EXEMPT_IPS` plus automatic
  exemption of `EXTERNAL_ADMIN` / `EXTERNAL_FRONTEND` (the portal host sits at a hosting provider —
  without this the block would take the site down); and the empty-store case above.

**Refresher** (`cloud_range_refresh.hpp/.cpp`) — an in-process thread on a fortnightly timer,
mirroring `envfish-db/mssql/tools/Update-CloudProviderRanges.ps1` feed for feed: AWS, GCP, Oracle
and DigitalOcean first-party feeds, the weekly Azure ServiceTags file (link scraped from the
download page), and RIPEstat announced-prefixes for Alibaba/Linode/Vultr/Hetzner/OVH/Scaleway/
Tencent. Both quirks that script documents are carried over: GCP entries with no `ipv4Prefix` are
guarded, and DigitalOcean's CSV arrives without a text content-type. Rows for the providers that
succeeded are replaced in one transaction with `disabled` overrides preserved per `(provider,
cidr)`; a failed feed keeps its own rows, and if every feed fails the database is untouched. The
thread waits on a condition variable, so shutdown never blocks on the two-week timer.

**TLS was turned on for this.** `HTTPLIB_USE_OPENSSL_IF_AVAILABLE` was deliberately `OFF` and the
reasoning still holds for the proxy path (still plain HTTP to docapi over the VPC), but every
provider feed is HTTPS-only. 0.8.0 accepts the trade knowingly: libssl joins libcrypto, the image
grows, `ca-certificates` becomes load-bearing, and the proxy makes outbound internet calls it never
made before. nlohmann/json (header-only) was added to parse the feeds.

## Encrypted config (secret_codec + dotenv)

cproxy reads an optional dotenv file (`CPROXY_DOTENV_PATH`) and decrypts `enc:v1:` values in it,
byte-compatible with `secret/Protect-Env.ps1` and the Java `SecretCodec`.

- **Cipher:** AES-256-GCM (OpenSSL libcrypto), `enc:v1:base64url(nonce[12] ‖ ciphertext ‖ tag[16])`,
  AAD = the variable name. 32-byte key from `FF_MASTER_KEY_FILE` (hex or base64) or `FF_MASTER_KEY`.
- `secret_codec.cpp`: `is_encrypted`, `decrypt_if_needed(name, value)` (lazy-cached key; throws on
  missing/wrong key or tamper). `dotenv.cpp`: `load_dotenv(path)` (parse `KEY=VALUE`, decrypt marked
  values; missing file → empty) and `make_env_lookup(map)` (real env wins, then dotenv).
- `main` resolves `CPROXY_DOTENV_PATH` from the real env, loads+decrypts the dotenv, then
  `load_config(make_env_lookup(dotenv))`. A decrypt failure is fatal (exit 1) before the server binds.
- `EXTERNAL_ADMIN` / `EXTERNAL_FRONTEND` → `Config.external_admin` / `.external_frontend`; **masked in
  logs** (only `set`/`unset`). In prod the `.env` + `master.key` live on the mounted volume, read-only.
- Tests: `secret_codec_test` decrypts a fixture generated by the .NET AesGcm (cross-impl proof);
  `config_test` covers the external fields.

## Logging

Same functionality as `waterservice`'s logback config, implemented in C++ (`log.hpp/.cpp`) since there
is no logback: structured **JSON** to **console** (`docker logs`) and a **daily-rolling file**.

- Active file `<CPROXY_LOG_DIR>/cproxy.log`; on the first write of a new UTC day it rolls to
  `cproxy.<YYYY-MM-DD>.log` (logback `TimeBasedRollingPolicy`) and prunes files older than
  `CPROXY_LOG_MAX_HISTORY` days (`maxHistory`, default 7).
- One mutex serializes all writes; each line is flushed for durability. `CPROXY_LOG_DIR=NONE` →
  console-only. The sentinel is the switch, not `""`: an empty value reads as unset (see Config
  above), so `-e CPROXY_LOG_DIR=` drops to the compiled-in default `logs` and still writes files.
  A log directory that cannot be created or opened silently degrades to console-only.
- `main` calls `init_logging(cfg.log_dir, cfg.log_max_history)` before anything else and emits the
  startup line via `log_raw`; the proxy handler emits one `log_line` per proxied request
  (`{"ts","service":"cproxy","msg":"<method> <path> -> <status> (<ms>)"}`). Only `/api/*` requests log
  a line — `/health` and 404s do not.
- Docker image defaults `CPROXY_LOG_DIR=/var/log/cproxy`, pre-created owned by uid 10001; production
  bind-mounts a persistent DO volume there.

- `config` + `proxy` compile into a `cproxy_core` static library so both `main` and the tests link
  them (enables testing config apart from the server).
- Routing uses `httplib::Server::set_pre_routing_handler`, called for every method+path — one place
  to serve `/health`, forward the prefix, and 404 the rest. This is why all verbs forward uniformly
  with no per-method route registration.
- Logging: one JSON line per request to stdout (guarded by a mutex), visible via `docker logs`.

## HTTP engine

cpp-httplib (yhirose/cpp-httplib), header-only server **and** client, fetched by CMake FetchContent
pinned to `v0.15.3`. TLS/zlib/brotli integrations are forced OFF: cproxy speaks plain HTTP to internal
upstreams, so the binary carries no libssl/libz dependency. Public TLS termination is a fronting
concern, added later, not this process's job.

## Build

- CMake ≥ 3.20, C++23 (`CMAKE_CXX_STANDARD 23`, extensions off), Release by default.
- `cmake -S . -B build && cmake --build build --parallel && ctest --test-dir build --output-on-failure`.

## Docker

Multi-stage. **Build stage** `debian:trixie`: apt `build-essential cmake git ca-certificates`,
configure + build Release, then `ctest` (a failing test fails the image). **Runtime stage**
`debian:trixie-slim`: apt `wget ca-certificates`, non-root uid 10001, copy the `cproxy` binary,
`EXPOSE 8080`, `HEALTHCHECK wget -qO- /health`, `ENTRYPOINT /usr/local/bin/cproxy`. Base images should
be pinned by digest for release reproducibility (sibling-service convention).

## Deployment (LIVE + committed — 2026-08-25)

Deployed on droplet `<cproxy-droplet>` as `ghcr.io/balintomsk/cproxy:0.6.1` (SSH key
`efc-proxy/secret/proxy`; GHCR token `efc-proxy/secret/ghcr.token`), via `docker compose`
(`/opt/cproxy/compose.yml`, image pinned by digest) behind a `DOCKER-USER` allowlist firewall,
published on port 80, **`GET` + day-key-gated `PATCH`** (was GET-only through 0.5.1), logs on the
`volume-cnode` DO volume. Since 0.2.0 the service also has:
encrypted config (0.3.0), security hardening + allowlist (0.4.0), pooled upstream + circuit breaker +
`/health/ready` + `/metrics` (0.5.0), the `mcrypter`/`_HIDD` env-name obfuscation (0.5.1), and the
SQLite-backed day-key store gating PATCH (0.6.0/0.6.1 — 0.6.1 fixed a Content-Type-forwarding bug
found live during the 0.6.0 rollout). Full
build→deploy procedure: `docs/do-update.md`. **Reachability is wired over the DigitalOcean VPC:** both droplets
share `eth1` `<vpc-cidr>`; docapi dual-publishes `127.0.0.1:8080` + `<docapi-vpc>:8080` (VPC, not
public) and `CPROXY_DOCAPI_UPSTREAM=http://<docapi-vpc>:8080`. See `CLAUDE.md` → Deployment/Reachability
for the exact run command and the docapi dual-bind (baked into the `update-docapi` skill).

**Version control:** the service is committed on `efc-proxy` `main` and pushed to
`github.com/BalinTomsk/efc-proxy`; the upstream docapi fish-search endpoint is merged to `efj-backend`
main (PR #85). Prod and git are in sync. Only `README.md` is tracked in `service/cproxy/` (this spec and
`CLAUDE.md` are gitignored local docs), and the tracked README must carry no external real IPs.

## Verification (2026-08-04, local Docker)

- Image `cproxy:0.1.0` built; `config_test` 1/1 in-build.
- `/health` → 200; unknown path → 404; `/api/...` with unreachable upstream → 502 honoring the
  1.5 s connect timeout, with a structured error + log line.
- End-to-end against a `traefik/whoami` echo upstream on a shared network: `GET /api/demo?x=1`
  reached the upstream with path+query intact and `X-Forwarded-For/-Host/-Proto` set; 200 returned.
- Guards: `CPROXY_API_KEY` → 401 without / 200 with `X-API-Key`; `CPROXY_ALLOWED_METHODS=GET` → 405
  on other methods; on a PATCH additionally in the allow-list, `CPROXY_DAYKEY_DB` unset/wrong
  `X-Day-Guid` → 500, the current UTC day's guid → forwarded normally
  on POST.
