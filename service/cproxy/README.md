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
| `CPROXY_DAYKEY_DB` | (empty) | path to the day-key SQLite db gating POST/PATCH; empty ⇒ POST/PATCH always `500` |
| `CPROXY_CONNECT_TIMEOUT_MS` | `3000` | upstream connect timeout |
| `CPROXY_READ_TIMEOUT_MS` | `10000` | upstream read timeout |
| `CPROXY_MAX_PAYLOAD_BYTES` | `1048576` | request bodies above this are rejected with `413` |
| `CPROXY_BREAKER_THRESHOLD` | `5` | consecutive upstream failures before failing fast (`0` disables) |
| `CPROXY_BREAKER_COOLDOWN_MS` | `5000` | how long the breaker stays open before allowing one probe |
| `CPROXY_UPSTREAM_RETRY` | `1` | retry idempotent requests once on a transport failure (`0` disables) |
| `CPROXY_LOG_DIR` | `logs` (image: `/var/log/cproxy`) | rolling-log directory; `""` = console-only |
| `CPROXY_LOG_MAX_HISTORY` | `7` | days of rolled log files to keep |

See `.env.example`. No config file — everything is env, so one image runs anywhere.

## Logging

Same functionality as the sibling `waterservice`: structured **JSON** lines to **both** the console
(`docker logs`) and a **daily-rolling file** with bounded retention. The active file is
`<CPROXY_LOG_DIR>/cproxy.log`; at the first write of each new UTC day it rolls to
`cproxy.<YYYY-MM-DD>.log` and files older than `CPROXY_LOG_MAX_HISTORY` days are pruned. In production
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

### Day-key store (the write surface's credential)

`POST` and `PATCH` requests (the gate applies to every POST/PATCH, not a specific path — every
docapi write, from `river/fish/{guid}` PATCH to `river/regulation/{guid}` and
`region/regulation/{country}[/{state}]` PATCH, clears the same check) are gated by a **second,
independent** control on
top of `CPROXY_API_KEY`/`CPROXY_ALLOWED_METHODS`: a per-day rotating GUID read from a small read-only
SQLite database at `CPROXY_DAYKEY_DB` (`day_keys(day_of_year, guid)`, exactly 365 rows). A caller
sends the current UTC day's GUID in `X-Day-Guid` (a ±1-day window is accepted); a wrong or missing
value answers a plain `500`, never `401` — the failure looks identical to an ordinary server error to
anyone probing it. The database is generated out-of-band (never from source) and deployed like any
other secret — see `secret/daykeys.sqlite` (gitignored) and `CLAUDE.md` → "Day-key store" for the
full design and deploy path.

## Tests

`ctest` runs five suites: `config_test` (config parsing — defaults, overrides, method allow-list,
malformed-value fallback), `secret_codec_test`, `proxy_test`, `breaker_test`, and
`day_key_store_test` (the yesterday/today/tomorrow window, both directions of the year boundary, the
leap-day-366 clamp, and the fail-loud-on-a-bad-database cases). Proxy behaviour is also verified by
running the container against a reachable echo upstream (see `docs/specification.md`).
