#pragma once

#include <httplib.h>

#include "config.hpp"

namespace cproxy {

/**
 * Installs cproxy's request handling onto the server:
 *   - GET /health                      -> local liveness JSON (never forwarded, never upstream-dependent)
 *   - GET /health/ready                -> readiness; 503 while the upstream circuit breaker is open
 *   - GET /metrics                     -> Prometheus text counters
 *   - <route_prefix>...  (e.g. /api/)   -> reverse-proxied to the docapi upstream
 *   - anything else                    -> 404
 *
 * Forwarding preserves method, the raw request target, headers (minus hop-by-hop and any inbound
 * X-Forwarded or X-Request-Id), and body; adds the standard X-Forwarded headers and a correlation
 * id; enforces the optional API key and method allow-list; rejects path traversal; and maps an
 * unreachable/timed-out upstream to a clean 502. Upstream connections are pooled per worker thread,
 * guarded by a consecutive-failure circuit breaker that fails fast during an outage.
 *
 * Each call creates its own breaker and counters, so several proxies can coexist in one process.
 * `cfg` must outlive `server` (the handlers hold a reference to it).
 */
void install_routes(httplib::Server& server, const Config& cfg);

}  // namespace cproxy
