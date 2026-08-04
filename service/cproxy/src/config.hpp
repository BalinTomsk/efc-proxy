#pragma once

#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace cproxy {

/**
 * Runtime configuration, entirely from environment variables so the same image runs in
 * any environment without a rebuild. All values have safe defaults.
 *
 * | Variable                    | Default                       | Meaning                                   |
 * |-----------------------------|-------------------------------|-------------------------------------------|
 * | CPROXY_LISTEN_ADDR          | 0.0.0.0                       | bind address                              |
 * | CPROXY_LISTEN_PORT          | 8080                          | bind port                                 |
 * | CPROXY_DOCAPI_UPSTREAM      | http://127.0.0.1:8080         | docapi origin (scheme://host:port)        |
 * | CPROXY_ROUTE_PREFIX         | /api/                         | path prefix forwarded to docapi           |
 * | CPROXY_API_KEY              | (empty)                       | if set, require header X-API-Key to match |
 * | CPROXY_ALLOWED_METHODS      | (empty = all)                 | CSV allow-list, e.g. "GET,HEAD"           |
 * | CPROXY_CONNECT_TIMEOUT_MS   | 3000                          | upstream connect timeout                  |
 * | CPROXY_READ_TIMEOUT_MS      | 10000                         | upstream read timeout                     |
 * | CPROXY_MAX_PAYLOAD_BYTES    | 1048576 (1 MiB)               | request bodies above this are rejected 413|
 * | CPROXY_BREAKER_THRESHOLD    | 5 (0 = disabled)              | consecutive upstream failures to open     |
 * | CPROXY_BREAKER_COOLDOWN_MS  | 5000                          | fail-fast window before a probe is allowed |
 * | CPROXY_UPSTREAM_RETRY       | 1 (0 = off)                   | retry idempotent requests once on transport failure |
 * | CPROXY_LOG_DIR              | logs                          | rolling-log directory ("" = stdout only)  |
 * | CPROXY_LOG_MAX_HISTORY      | 7                             | days of rolled log files to keep          |
 */
struct Config {
    std::string listen_addr = "0.0.0.0";
    int listen_port = 8080;
    // Neutral local default; production always sets CPROXY_DOCAPI_UPSTREAM explicitly (the real
    // docapi address is deployment config, not a source-code constant).
    std::string docapi_upstream = "http://127.0.0.1:8080";
    std::string route_prefix = "/api/";
    std::string api_key;                    // empty => no auth required
    std::set<std::string> allowed_methods;  // empty => all methods allowed (stored upper-case)
    int connect_timeout_ms = 3000;
    int read_timeout_ms = 10000;
    int max_payload_bytes = 1 * 1024 * 1024;  // GET-only JSON API: nobody legitimately sends more
    int breaker_threshold = 5;                // consecutive upstream failures before failing fast
    int breaker_cooldown_ms = 5000;           // how long the breaker stays open before probing
    // A pooled keep-alive connection can be closed by the upstream while idle, so the first send
    // on it fails through no fault of the request; one retry hides that. Idempotent methods only.
    int upstream_retry = 1;
    std::string log_dir = "logs";  // "" => console only; the Docker image sets an absolute path
    int log_max_history = 7;       // days of rolled log files to keep

    // Values typically supplied via an encrypted dotenv on the volume (EXTERNAL_ADMIN / EXTERNAL_FRONTEND);
    // decrypted at load time. Empty when not configured.
    std::string external_admin;     // e.g. an admin source IP (secret)
    std::string external_frontend;  // e.g. the frontend host

    /** Case-insensitive method allow-list check. Empty allow-list => everything permitted. */
    bool method_allowed(const std::string& method) const;

    /** True when CPROXY_API_KEY is set and callers must present a matching X-API-Key. */
    bool auth_required() const { return !api_key.empty(); }
};

/** Abstraction over getenv so config parsing is pure and unit-testable. */
using EnvLookup = std::function<std::optional<std::string>(const char*)>;

/** Default lookup backed by std::getenv (empty string is treated as "unset"). */
std::optional<std::string> system_env(const char* name);

/** Builds a Config from the given environment lookup (defaults to the process environment). */
Config load_config(const EnvLookup& env = system_env);

/**
 * Sanity-checks a loaded Config. Returns one human-readable message per problem; an empty vector
 * means the config is usable. Startup treats any problem as fatal (fail fast beats limping along
 * with a port of 0 or a negative timeout).
 */
std::vector<std::string> validate_config(const Config& cfg);

}  // namespace cproxy
