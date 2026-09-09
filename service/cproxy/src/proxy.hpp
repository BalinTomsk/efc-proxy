#pragma once

#include <httplib.h>

#include "cloud_range_store.hpp"
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
 * id; enforces the optional API key, method allow-list, and (for POST/PATCH) the day-key credential;
 * rejects path traversal; and maps an unreachable/timed-out upstream to a clean 502. Upstream
 * connections are pooled per worker thread, guarded by a consecutive-failure circuit breaker that
 * fails fast during an outage.
 *
 * Every POST and PATCH additionally requires the gateway credential, as does any path in
 * `CPROXY_DAYKEY_PATHS`. As of 0.10.0 that credential is an `Authorization: Bearer <HS512 JWT>` whose
 * `server` claim carries the current UTC day's key (yesterday/today/tomorrow window) from
 * `cfg.daykey_db_path` — see DayKeyStore and jwt_verifier.hpp — and whose `user` claim is checked
 * against the account mirror when `CPROXY_JWT_REQUIRE_USER` is on (UserPrimeStore). The pre-0.10.0
 * raw `X-Day-Guid` header still clears the gate until `CPROXY_JWT_REQUIRED` is turned on, so the two
 * services can be deployed in either order. A missing/wrong credential is answered with a generic
 * 500, not 401, so it reads no differently from an ordinary server error to anyone probing the
 * endpoint. This is orthogonal to CPROXY_ALLOWED_METHODS: POST/PATCH must still be in the allow-list
 * for a request to reach this check at all.
 *
 * A request whose peer address falls in `cfg.cloudrange_db_path`'s datacenter ranges is refused
 * with the same generic 500 before any other guard runs — see CloudRangeStore. Exempt addresses
 * (the frontend host, the admin IP, `CPROXY_CLOUDRANGE_EXEMPT_IPS`) short-circuit first, and
 * `CPROXY_BLOCK_CLOUD_IPS=false` disables the refusal without a redeploy.
 *
 * Each call creates its own breaker and counters, so several proxies can coexist in one process.
 * `cfg` must outlive `server` (the handlers hold a reference to it).
 *
 * `shared_ranges`, when non-null, is used INSTEAD of a privately-loaded range set, so the refresh
 * thread's atomic swap is seen by live traffic without a restart. It must outlive `server`. Tests
 * pass nullptr and get a private store loaded from the config path.
 */
void install_routes(httplib::Server& server, const Config& cfg,
                    CloudRangeStore* shared_ranges = nullptr);

}  // namespace cproxy
