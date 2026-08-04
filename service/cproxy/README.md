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
| `GET /health` | local liveness JSON `{ status, service, version }` — never forwarded |
| `<CPROXY_ROUTE_PREFIX>…` (default `/api/`) | reverse-proxied to the docapi upstream |
| anything else | `404` |

Forwarding preserves the method, path + query string, headers (minus hop-by-hop), and body; adds
`X-Forwarded-For` / `-Host` / `-Proto`; and maps an unreachable or slow upstream to a clean `502`.
Two optional edge guards: an **API key** (`X-API-Key`) and a **method allow-list** (e.g. GET-only).

## Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `CPROXY_LISTEN_ADDR` | `0.0.0.0` | bind address |
| `CPROXY_LISTEN_PORT` | `8080` | bind port |
| `CPROXY_DOCAPI_UPSTREAM` | `http://11.13.196.12:8080` | docapi origin (`scheme://host:port`) |
| `CPROXY_ROUTE_PREFIX` | `/api/` | path prefix forwarded to docapi |
| `CPROXY_API_KEY` | (empty) | if set, callers must send `X-API-Key: <value>` |
| `CPROXY_ALLOWED_METHODS` | (empty = all) | CSV allow-list, e.g. `GET,HEAD` |
| `CPROXY_CONNECT_TIMEOUT_MS` | `3000` | upstream connect timeout |
| `CPROXY_READ_TIMEOUT_MS` | `10000` | upstream read timeout |
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

## Build & run (local)

Requires CMake ≥ 3.20 and a C++23 compiler (GCC 13+/Clang 16+). cpp-httplib is fetched automatically.

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

## Deployed (2026-08-04)

Live at **`http://10.12.22.225/`** (`ghcr.io/balintomsk/cproxy:0.2.0`, port 80, GET-only, logs on the
`volume-cnode` DO volume at `/mnt/volume_cnode/cproxy/logs`). Reachability
is wired over the VPC : both VPS share `eth1` `10.112.0.0/20`, docapi is published
on `10.112.32.3:8080` (VPC) in addition to `127.0.0.1:8080`, and `CPROXY_DOCAPI_UPSTREAM=http://10.112.32.3:8080`.
docapi stays private (not bound to `0.0.0.0`; `10.112.32.3:8080` refuses from the internet).  

The docapi dual-bind is baked into that service's `update-docapi` skill so future docapi deploys keep it.
See `CLAUDE.md` → Deployment for the run command and lock-down options.

## Tests

`ctest` runs `config_test` — framework-free assertions over config parsing (defaults, overrides,
method allow-list, malformed-value fallback). Proxy behaviour is verified by running the container
against a reachable echo upstream (see `docs/specification.md`).
