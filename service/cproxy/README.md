# cproxy

`cproxy` is a small **C++23 reverse proxy**. It is the edge between the ASP.NET frontend
 and the internal backend VPS, and runs in a Docker container on Debian 13
("trixie") on VPS 

Its job is to give frontend.service a single REST entry point and forward requests inward to the
backend services. **Today it fronts one upstream — the `docapi` service**  . It is built to grow: the other backend VPS
  becomes an additional upstream by adding a route, no redesign needed.

```
frontend.service ──HTTP──►  cproxy (10.12.22.225)  ──HTTP──►  docapi   (10.13.16.66)
                          /api/*  →  docapi                 └►  (future) 13.11.28.11
                          /health →  local
```

## What it does

| Path | Behaviour |
|------|-----------|
| `GET /health` | local liveness JSON `{ status, service, version }` — never forwarded, never upstream-dependent |
| `GET /health/ready` | readiness — `503` while the upstream circuit breaker is open |
| `GET /metrics` | Prometheus text counters (requests by status, upstream latency, failures, breaker state) |
| `<CPROXY_ROUTE_PREFIX>…` (default `/api/`) | reverse-proxied to the docapi upstream |
| anything else | `404` |

Forwarding preserves the method, the **raw** request target (exact bytes — no decode/re-encode round
trip), headers (minus hop-by-hop and inbound `X-Forwarded-*`/`X-Request-Id`, which the proxy sets
itself), and body; adds `X-Forwarded-For` / `-Host` / `-Proto`; and maps an unreachable or slow
upstream to a clean `502`. Two optional edge guards: an **API key** (`X-API-Key`, compared in
constant time) and a **method allow-list** (e.g. GET-only).

Reliability: upstream connections are **pooled per worker thread** with keep-alive (rather than a
fresh TCP connect per request), a transport failure on an idempotent request is **retried once**
(mainly to hide a pooled connection the upstream closed while idle), and a **consecutive-failure
circuit breaker** stops dialing a dead upstream after `CPROXY_BREAKER_THRESHOLD` failures — during
an outage requests get an immediate `502 upstream_unavailable` instead of each paying the full
connect timeout and holding a worker thread. After the cooldown one probe is allowed through;
success closes the breaker. HTTP error statuses from a *reachable* upstream are the upstream's
answer, not transport failures, and never trip it.

Edge hardening: any target with a `..` path segment (plain or percent-encoded) is rejected with
`400` before it can reach an upstream that might normalize it out of the route prefix; request
bodies above `CPROXY_MAX_PAYLOAD_BYTES` are cut off with `413`; malformed startup config is a fatal
error (fail fast). Every request carries an **`X-Request-Id`** — a well-formed caller-supplied id is
preserved, anything else is re-minted — propagated to the upstream, echoed in the response, and
logged (`reqid`) together with the client IP (`ip`), including on unmatched-path `404`s so scanner
probing is visible.

## Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `CPROXY_LISTEN_ADDR` | `0.0.0.0` | bind address |
| `CPROXY_LISTEN_PORT` | `8080` | bind port |
| `CPROXY_DOCAPI_UPSTREAM` | `http://11.13.196.12:8080` | docapi origin (`scheme://host:port`) |
| `CPROXY_ROUTE_PREFIX` | `/api/` | path prefix forwarded to docapi |
| `CPROXY_API_KEY` | (empty) | if set, callers must send `X-API-Key: <value>` |
| `CPROXY_ALLOWED_METHODS` | (empty = all) | CSV allow-list, e.g. `GET,HEAD` |
| `CPROXY_DAYKEY_DB` | (empty) | path to the day-key SQLite db; empty ⇒ every gated request always `500` |
| `CPROXY_DAYKEY_PATHS` | `/news/default,/news/featured,/news/more,/news/photo` | CSV of paths day-key gated on **every** method, `GET` included; `NONE` disables (an empty value reads as unset) |
| `CPROXY_JWT_SECRET` | (empty) | HS512 shared secret; empty ⇒ every gated request always `500` (the Bearer token is the only credential) |
| `CPROXY_JWT_REQUIRE_USER` | `false` | `true` ⇒ writes must carry a `user` claim, and any claim present must match a live account |
| `CPROXY_JWT_ISSUER` | `envfish` | required `iss`; `NONE` skips the check |
| `CPROXY_JWT_AUDIENCE` | `fishfind.info` | required `aud`; `NONE` skips the check |
| `CPROXY_JWT_SUBJECT` | `cproxy` | required `sub`; `NONE` skips the check |
| `CPROXY_JWT_LEEWAY_SECONDS` | `300` | clock-skew allowance on `exp`/`iat`/`nbf` (**prod sets 60**) |
| `CPROXY_JWT_USER_CACHE_SECONDS` | `60` | how long the account-prime snapshot is reused (also the revocation lag) |
| `CPROXY_JWT_CLOCK_SYNC` | `true` | allow an admin account's token (mirror `access = 255`) + `X-Client-Time` to correct the credential clock offset (never the system clock) |
| `CPROXY_JWT_CLOCK_SYNC_THRESHOLD_SECONDS` | `5` | smallest disagreement worth correcting |
| `CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS` | `3600` | ceiling on the TOTAL offset — the security bound on the feature |
| `CPROXY_CLOUDRANGE_DB` | (empty) | SQLite datacenter-IP range db; empty ⇒ feature off entirely |
| `CPROXY_BLOCK_CLOUD_IPS` | `true` | kill-switch — `false` keeps the data and refresh but refuses nothing |
| `CPROXY_CLOUDRANGE_REFRESH_HOURS` | `336` | interval between provider-feed refreshes (fortnightly) |
| `CPROXY_CLOUDRANGE_REFRESH_ON_START` | `false` | fetch once at boot instead of waiting a full interval |
| `CPROXY_CLOUDRANGE_PROVIDERS` | (all 12) | CSV of feeds; `NONE` stops refreshing but keeps blocking |
| `CPROXY_CLOUDRANGE_EXEMPT_IPS` | (empty) | never blocked (admin + frontend are exempt automatically) |
| `CPROXY_RABBITMQ_EVENTS_ENABLED` | `false` | consume frontend account/API-key events from RabbitMQ into local SQLite |
| `CPROXY_RABBITMQ_MANAGEMENT_URL` | (empty) | RabbitMQ HTTPS management API used for queue polling; required (`scheme://host[:port]`) when events are enabled — no default, set via the encrypted dotenv like `CPROXY_RABBITMQ_PASSWORD` |
| `CPROXY_RABBITMQ_USERNAME` | `fishfind` | RabbitMQ user for account-event consumption |
| `CPROXY_RABBITMQ_PASSWORD` | (empty) | RabbitMQ password; required when events are enabled; keep in encrypted dotenv |
| `CPROXY_RABBITMQ_QUEUE` | `fishfind.account.events` | durable queue carrying account and API-key events |
| `CPROXY_ACCOUNT_MIRROR_DB` | `/var/lib/cproxy/auth.sqlite` | local SQLite mirror for `Users`, `user_api_key`, and raw account events |
| `CPROXY_RABBITMQ_POLL_MS` | `1000` | delay between empty/failed RabbitMQ polls |
| `CPROXY_RABBITMQ_BATCH_SIZE` | `25` | max messages consumed per RabbitMQ poll |
| `CPROXY_CONNECT_TIMEOUT_MS` | `3000` | upstream connect timeout |
| `CPROXY_READ_TIMEOUT_MS` | `10000` | upstream read timeout |
| `CPROXY_MAX_PAYLOAD_BYTES` | `1048576` | request bodies above this are rejected with `413` |
| `CPROXY_BREAKER_THRESHOLD` | `5` | consecutive upstream failures before failing fast (`0` disables) |
| `CPROXY_BREAKER_COOLDOWN_MS` | `5000` | how long the breaker stays open before allowing one probe |
| `CPROXY_UPSTREAM_RETRY` | `1` | retry idempotent requests once on a transport failure (`0` disables) |
| `CPROXY_LOG_DIR` | `logs` (image: `/var/log/cproxy`) | rolling-log directory; `NONE` = console-only (an empty value reads as unset) |
| `CPROXY_LOG_MAX_HISTORY` | `7` | days of rolled log files to keep |

See `.env.example`. No config file — everything is env, so one image runs anywhere.

**An empty value always means "use the default."** `getenv() == ""` is indistinguishable from unset,
so every switch spells its *off* state as a word instead: `CPROXY_ALLOWED_METHODS=ALL`,
`CPROXY_DAYKEY_PATHS=NONE`, `CPROXY_LOG_DIR=NONE` (case-insensitive, trimmed). `-e CPROXY_LOG_DIR=`
does **not** turn file logging off — it falls back to `logs`.

## Datacenter / cloud-provider IP blocking

A REST call whose peer address falls in published datacenter space is refused with an opaque `500`
before any other guard runs. This is the cproxy half of the frontend's `dbo.CloudProviderIpRange`
control (see `aspnet/Account/CLAUDE.md`): real anglers come from residential and mobile ISPs, so
sustained traffic from AWS/GCP/Azure/Oracle/DigitalOcean/Alibaba and friends is bots and scrapers.

- **Same shape as the frontend's table** — one row per published CIDR, expanded to an inclusive
  numeric `[ip_start, ip_end]` window, with a `disabled` flag as a manual per-row override that the
  refresh preserves per `(provider, cidr)`.
- **Ranges are coalesced in memory.** The frontend's single-seek SQL is only correct while ranges
  are disjoint; across twelve feeds they are not. Merging overlapping and adjacent intervals makes
  the binary search correct unconditionally — and collapses ~92k raw rows to under 4k intervals.
- **The peer address comes from the TCP connection, never `X-Forwarded-For`.** cproxy is the edge,
  so an inbound XFF is attacker-controlled: trusting it would let anyone bypass the block, or get a
  third party blocked, just by setting a header.
- **`500`, not `403`** — identical to a failed day-key, so probing the gateway reveals nothing.

**Three escape hatches, because a wrong range takes the portal offline.** `CPROXY_BLOCK_CLOUD_IPS=false`
disables refusal without a redeploy; `CPROXY_CLOUDRANGE_EXEMPT_IPS` (plus `EXTERNAL_ADMIN` /
`EXTERNAL_FRONTEND`, exempt automatically) allowlists individual addresses; and an empty or missing
database blocks nothing, which is also the state before the first refresh.

The refresher runs in-process on a fortnightly timer, fetching each provider's published feed over
HTTPS and rewriting the database in one transaction. A feed that fails leaves its own rows intact;
if every feed fails the database is not touched at all.

> **This is why the binary links libssl.** cpp-httplib TLS was deliberately off ("cproxy speaks
> plain HTTP to internal upstreams") and that still holds for the proxy path — but the provider
> feeds are HTTPS-only, so 0.8.0 turns TLS on and gives the proxy outbound internet egress it did
> not previously have. `ca-certificates` in the runtime image is load-bearing from here on.


## RabbitMQ account-event mirror

When `CPROXY_RABBITMQ_EVENTS_ENABLED=true`, cproxy polls RabbitMQ's HTTPS management API at
`CPROXY_RABBITMQ_MANAGEMENT_URL`, consumes the durable queue `fishfind.account.events`, and writes
an idempotent local SQLite mirror to `CPROXY_ACCOUNT_MIRROR_DB`. The mirror has four tables:
`account_events` for raw event audit, `users` for the registration/OAuth profile snapshot,
`users_sync` for the full `dbo.Users` row mirror (see below), and `user_api_key` for API-key
issue/disable/enable/delete state.

The RabbitMQ management URL and password are both deployment secrets, not tracked values — this
repo is public. In production put `CPROXY_RABBITMQ_MANAGEMENT_URL=<url>` and
`CPROXY_RABBITMQ_PASSWORD=<password>` in the encrypted dotenv mounted at `/etc/cproxy/.env`; do not
put either in tracked `deploy/compose.yml`.

Frontend publishers emit these event types:

- `fishfind.account.user` with actions `registered`, `oauth_registered`, and `oauth_login`.
- `fishfind.account.api_key` with actions `issued`, `disabled`, `enabled`, and `deleted`.
- `fishfind.account.user_sync` with actions `created` and `updated`, emitted by
  `fishfind-frontend/aspnet/tools/Run-UsersSyncDispatch.ps1` (a scheduled-task dispatcher, not app
  code) draining `dbo.UsersSyncOutbox`. `dbo.TR_Users_SyncOutbox` (envfish-db) appends to that outbox
  on **every** write to `dbo.Users`, including a manual admin `UPDATE` to `access`/`suspended`/
  `deleted` run directly against the table — there is no app code path for those today, so this is
  the only event type that reflects such changes. The `users_sync` table carries `id`, `users_id`
  (`dbo.Users.UsersId`), `user_name`, `email`, `last_visit`, `access`, `suspended`, `auth_type`,
  `deleted`, `deleted_utc`.

The consumer stores by `eventId` first, so replayed messages are harmless duplicates.
## Logging

Same functionality as the sibling `waterservice`: structured **JSON** lines to **both** the console
(`docker logs`) and a **daily-rolling file** with bounded retention. The active file is
`<CPROXY_LOG_DIR>/cproxy.log`; at the first write of each new UTC day it rolls to
`cproxy.<YYYY-MM-DD>.log` and files older than `CPROXY_LOG_MAX_HISTORY` days are pruned. Set
`CPROXY_LOG_DIR=NONE` for console-only. In production
the log directory is a   bind-mounted at `/var/log/cproxy`, so logs survive
container redeploys and reboots.

## Encrypted config

cproxy can read an extra dotenv file (`CPROXY_DOTENV_PATH`) and decrypt individually-encrypted values
in it, using the **same scheme as the platform's `secret/Protect-Env.ps1` and the Java `SecretCodec`**
(docapi/waterservice): **AES-256-GCM**, values stored as `enc:v1:<base64url(nonce ‖ ciphertext ‖ tag)>`
with the variable name bound in as AAD. The 32-byte master key comes from `FF_MASTER_KEY_FILE`
(hex/base64). A real process environment variable always overrides a dotenv value; an `enc:v1:` value
with a missing/wrong key is a **fatal startup error** (never a silent pass-through).

`EXTERNAL_ADMIN` and `EXTERNAL_FRONTEND` are carried this way. Edit the plaintext in
`secret/plaintext.env`, then:

```powershell
./secret/Protect-Env.ps1 -GenerateKey   # once, creates secret/master.key
./secret/Protect-Env.ps1                 # encrypt plaintext.env -> secret/.env
./secret/Protect-Env.ps1 -Verify         # confirm round-trip (prints no secret values)
```

In production the encrypted `.env` and the `master.key` live on the mounted volume and are bind-mounted
into the container read-only; secret values are **masked in logs** (only their presence is recorded).
`secret/.env`, `secret/master.key`, and `secret/plaintext.env` are gitignored — never committed.

## Build & run (local)

Requires CMake ≥ 3.20, a C++23 compiler (GCC 13+/Clang 16+), and OpenSSL dev headers (`libssl-dev`;
libcrypto powers the secret codec). cpp-httplib is fetched automatically.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/cproxy            # listens on :8080
curl localhost:8080/health
```

## Docker

```bash
docker build -t cproxy:0.1.0 .
docker run -d --name cproxy -p 127.0.0.1:8080:8080 \
  -e CPROXY_DOCAPI_UPSTREAM=http://<docapi-host>:8080 cproxy:0.1.0
```

Multi-stage build (Debian trixie → trixie-slim); the unit tests run **inside** the build, so a broken
build never ships. Runs as non-root uid 10001; `HEALTHCHECK` hits `/health`.

## Deployed (2026-08-25)

Live at **`http://10.12.22.225/`** (`ghcr.io/balintomsk/cproxy:0.6.1`, deployed via `docker compose`
with the image pinned by digest, port 80 behind an allowlist firewall, logs on the
`volume-cnode` DO volume at `/mnt/volume_cnode/cproxy/logs`). Reachability
is wired over the VPC : both VPS share `eth1` `10.112.0.0/20`, docapi is published
on `10.112.32.3:8080` (VPC) in addition to `127.0.0.1:8080`, and `CPROXY_DOCAPI_UPSTREAM=http://10.112.32.3:8080`.
docapi stays private (not bound to `0.0.0.0`; `10.112.32.3:8080` refuses from the internet).

**Allowed methods: `GET` and `PATCH`** (was GET-only through 0.5.1) — PATCH is admitted only for the
day-key-gated write surface (see "Day-key store" above); every other write verb still 405s.

The docapi dual-bind is baked into that service's `update-docapi` skill so future docapi deploys keep it.
See `CLAUDE.md` → Deployment for the run command and lock-down options.

## Access control & hardened run config (`deploy/`)

The public edge is **allowlist-only**: `deploy/cproxy-firewall.sh` fills the `DOCKER-USER` iptables
chain — the one chain Docker-published ports actually honor (ufw/`INPUT` is bypassed by Docker's NAT) —
so that only the callers listed in `/usr/local/etc/cproxy-firewall.allow` (one IP/CIDR per line; see
`deploy/cproxy-firewall.allow.example`) reach the published port. Everyone else is dropped; replies to
container-initiated outbound stay open; the VPC interface and SSH are untouched, so applying it can
never lock out administration. A missing allow file **fails closed** (drop-all). IPv6 is closed too.
`deploy/cproxy-firewall.service` (systemd oneshot, `After=docker.service`) reapplies the rules on every
boot. Real deploy addresses live only in the host-side allow file, never in git.

One gotcha the allowlist surfaced: on shared hosting the frontend's **outbound egress IP can differ
from its A record** — verify it with a temporary server-side probe page (fetch an IP-echo service +
cproxy `/health`) before trusting DNS.

The container itself runs from `deploy/compose.yml` (kept at `/opt/cproxy/compose.yml` on the host):
image **pinned by digest**, `read_only` rootfs, `cap_drop: ALL`, `no-new-privileges`, restart policy,
and the log/secret bind mounts — replacing the previous hand-typed `docker run`.

### Day-key store (the rotating credential)

Some requests are gated by a **second, independent** control on top of
`CPROXY_API_KEY`/`CPROXY_ALLOWED_METHODS`: a per-day rotating GUID read from a small read-only SQLite
database at `CPROXY_DAYKEY_DB` (`day_keys(stamp TEXT PRIMARY KEY, guid TEXT NOT NULL)`, one row per
calendar date). A caller presents the current UTC day's GUID as the `server` claim of a signed Bearer
JWT (see below; a ±1-day window is accepted); a wrong or missing value answers a plain `500`, never
`401` — the failure looks identical to an ordinary server error to anyone probing it. Until 0.9.x the
GUID was sent bare in an `X-Day-Guid` header; since 0.13.0 that header is not read at all.

**Keyed by real date since 0.9.0.** It previously held exactly 365 rows indexed by day-of-year and
reused them annually, which could not represent the generated key set (date-keyed, spanning years) —
a 365-row projection agreed with it for about twelve months and then drifted. Matching on the date
makes every consumer agree by construction, and removed two special cases: the year-boundary wrap and
the leap-day clamp, under which 29 February reused 31 December's key. The store is finite, so startup
logs the covered range (`days`, `from`, `to`); past the last date every gated request fails closed
with the usual opaque `500` and nothing else says why.

Two arms decide what is gated, and either one is enough:

- **The whole write surface, by method** — every `POST` and `PATCH`, whatever the path, so every
  docapi write (`river/fish/{guid}`, `river/regulation/{guid}`,
  `region/regulation/{country}[/{state}]`, and anything added later) clears the same check with no
  configuration.
- **Named paths, by path** — `CPROXY_DAYKEY_PATHS`, default
  `/news/default,/news/featured,/news/more,/news/photo`. This is how a **read** is put behind the
  credential. **All four home-page endpoints are listed together on purpose:** docapi 1.8.1 split
  `/news/default` into `/news/featured` (the 2 lead articles, ~1.09 MB) and `/news/more` (the
  sidebar, ~1.6 KB), and docapi 1.9.0 added `/news/photo/{id}`, which serves those same lead photos
  as raw bytes. They all serve the *same* content — gating only `/news/default` leaves the rest as an
  unauthenticated bypass, which is what briefly happened after 1.8.1. If docapi splits or renames
  these again, add the new paths here in the same change; `/news/photo` was (0.14.0). `GET /api/v1/news/default` assembles the whole news home page
  upstream, and being a `GET` is not a reason to hand it to anonymous scrapers. Matching is on the
  path tail (so an entry works at any route prefix), case-folded, trailing-slash-insensitive, and
  covers anything nested underneath. Set `CPROXY_DAYKEY_PATHS=NONE` to turn this arm off — an empty
  value reads as *unset* and leaves the default in place.

The database is generated out-of-band (never from source) and deployed like any other secret — see
`secret/daykeys.sqlite` (gitignored) and `CLAUDE.md` → "Day-key store" for the full design and deploy
path.

### JWT credential (0.10.0; the only credential since 0.13.0)

The day-key travels **inside a signed token**, never on its own in a header. Callers send
`Authorization: Bearer <HS512 JWT>`:

```json
{ "iss": "envfish", "iat": 1788880000, "exp": 1788911999, "aud": "fishfind.info",
  "sub": "cproxy", "server": "<today's day-key GUID>", "user": "<Users.prime * Users_Prime.prime>" }
```

The token does **not** replace the rotation, it wraps it: `server` is still matched against the
day-key store exactly as the header was, so a leaked signing secret is worthless without today's GUID
and vice versa. What the signature adds is that the credential is bound to an issuer, an audience and
an expiry, so a copied request is no longer replayable from anywhere for the rest of the day. `user`
is the product of two primes issued once globally, which names one account on one day while revealing
neither factor; the gateway re-derives it from its own account mirror and never queries the
frontend's database.

- `HS512` is **pinned** — the token's own `alg` header is never obeyed, and `exp` is mandatory.
- Each segment must be **canonical base64url** (after 0.13.0): non-zero unused bits in a segment's
  last character are refused, so a token is accepted only exactly as minted, not in one of the
  equivalent spellings a lenient decoder would also map to the same bytes.
- **The token is the only credential.** The bare `X-Day-Guid` header (0.6.1–0.9.x, accepted
  alongside tokens through 0.12.0 until switched off) was removed in 0.13.0 together with the
  `CPROXY_JWT_REQUIRED` switch that governed it — a request carrying only the header, even with the
  correct key, is refused like one carrying nothing. With `CPROXY_JWT_SECRET` unset the gated surface
  is shut (startup logs an ERROR); ungated reads keep serving.
- Failure is the same opaque `500` as before. Bad signature, expired, and unknown account are
  indistinguishable from an ordinary server error.

`CPROXY_JWT_REQUIRE_USER=true` additionally demands a `user` claim on every write and checks any
claim that is present — it reads the account mirror, so verify the startup line `user-prime store
loaded` reports a non-zero account count before turning it on. Gated **reads** stay anonymous-capable
either way: `/news/featured` and `/news/more` are the public home page, and the gate there is against
scraping, not reading.

## Tests

`ctest` runs nine suites: `config_test` (config parsing — defaults, overrides, method allow-list,
malformed-value fallback), `secret_codec_test`, `proxy_test`, `breaker_test`, `day_key_store_test`
(the yesterday/today/tomorrow window, both directions of the year boundary, the leap-day-366 clamp,
and the fail-loud-on-a-bad-database cases), `cloud_range_store_test`, `account_mirror_store_test`,
`jwt_verifier_test` (forged signature, tampered payload, `alg:none`, an HS256 downgrade, expiry and
leeway, claim mismatches, malformed input), and `user_prime_store_test` (the prime product, a product
past 2^63, revoked/expired accounts, the day window, and a missing mirror failing closed). Proxy
behaviour is also verified by running the container against a reachable echo upstream (see
`docs/specification.md`).

