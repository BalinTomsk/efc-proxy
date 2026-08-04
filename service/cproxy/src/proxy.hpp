#pragma once

#include <httplib.h>

#include "config.hpp"

namespace cproxy {

/**
 * Installs cproxy's request handling onto the server:
 *   - GET /health                      -> local liveness JSON (never forwarded)
 *   - <route_prefix>...  (e.g. /api/)   -> reverse-proxied to the docapi upstream
 *   - anything else                    -> 404
 *
 * Forwarding preserves method, path+query, headers (minus hop-by-hop), and body, adds the
 * standard X-Forwarded-* headers, enforces the optional API key and method allow-list, and
 * maps an unreachable/timed-out upstream to a clean 502.
 */
void install_routes(httplib::Server& server, const Config& cfg);

}  // namespace cproxy
