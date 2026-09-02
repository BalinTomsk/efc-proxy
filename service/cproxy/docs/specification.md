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
- **Day-key guard:** independent of the two guards above — a gated request additionally requires
  `X-Day-Guid` to match the current UTC day's credential from the `CPROXY_DAYKEY_DB` SQLite database
  (±1 day window); a wrong or missing value → `500` (deliberately not `401`, so it reads no
  differently from an ordinary server error). Two arms, either one gates: **every POST/PATCH**
  whatever the path, and **every method on a path in `CPROXY_DAYKEY_PATHS`** (default
  `/news/default` — this is how a *read* is put behind the credential, added 0.7.0). Matching is on
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
| `CPROXY_DAYKEY_PATHS` | `/news/default` | CSV of paths day-key gated on **every** method, GET included; `NONE` disables (an empty value reads as unset) |
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
  day_key_store.hpp/.cpp  SQLite-backed per-day PATCH credential; DayKeyStore::is_valid()
  proxy.hpp/.cpp       install_routes(Server&, Config&): per-method routes; forwarding; PATCH day-key gate
  main.cpp             load config; init logging; SIGINT/SIGTERM -> server.stop(); listen
tests/
  config_test.cpp          framework-free assertions; registered with CTest
  day_key_store_test.cpp   yesterday/today/tomorrow window, year boundary, leap-day-366 clamp
  proxy_test.cpp           real HTTP through install_routes(); includes the gated-read cases
                           (/news/default 500 without a key, 502 through with one, siblings open)
```

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
