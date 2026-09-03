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
 * | CPROXY_LOG_DIR              | logs                          | rolling-log directory ("NONE" = stdout only) |
 * | CPROXY_LOG_MAX_HISTORY      | 7                             | days of rolled log files to keep          |
 * | CPROXY_DAYKEY_DB            | (empty)                       | path to the day-key SQLite db; POST/PATCH always 500 while empty |
 * | CPROXY_DAYKEY_PATHS         | /news/default,/news/featured,/news/more | CSV of paths day-key gated on EVERY method, GET included ("NONE" disables) |
 * | CPROXY_CLOUDRANGE_DB        | (empty)                       | SQLite datacenter-IP range db; empty = feature off |
 * | CPROXY_BLOCK_CLOUD_IPS      | true                          | kill-switch for refusing datacenter IPs   |
 * | CPROXY_CLOUDRANGE_REFRESH_HOURS | 336 (fortnightly)         | interval between provider-feed refreshes  |
 * | CPROXY_CLOUDRANGE_PROVIDERS | (all known)                   | CSV of provider feeds ("NONE" disables the refresh) |
 * | CPROXY_CLOUDRANGE_EXEMPT_IPS| (empty)                       | CSV never blocked (admin/frontend always exempt) |
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
    // Rolling-log directory; the Docker image sets an absolute path. Empty means console only, but
    // the way to ASK for that is CPROXY_LOG_DIR=NONE — an empty env value reads as "unset" and
    // leaves this default standing (see load_config).
    std::string log_dir = "logs";
    int log_max_history = 7;  // days of rolled log files to keep

    // Path to the day-key SQLite database (see DayKeyStore). Empty means day-key auth is not
    // configured, so every PATCH request fails closed with 500 regardless of CPROXY_ALLOWED_METHODS.
    std::string daykey_db_path;

    // --- Datacenter / cloud-provider IP blocking (mirrors the frontend's CloudProviderIpRange) ---
    // Path to the SQLite range database. Empty => the feature is off entirely: no blocking, and the
    // refresh thread never starts.
    std::string cloudrange_db_path;
    // Kill-switch equivalent to the frontend's BlockCloudProviderIps appSetting: false keeps the
    // database and the refresh running but stops refusing anything, so blocking can be dropped
    // without a redeploy.
    bool cloudrange_block_enabled = true;
    // Fortnightly by default. The published ranges move on the order of weeks, and every refresh
    // pulls ~100k prefixes from a dozen third-party feeds.
    int cloudrange_refresh_hours = 336;
    // Off by default: the stored set is already usable at boot, and refreshing on every start would
    // hammer the feeds during a redeploy loop.
    bool cloudrange_refresh_on_start = false;
    int cloudrange_fetch_timeout_seconds = 60;
    // Providers to fetch; defaults to every feed this build knows. "NONE" disables the refresh
    // while leaving enforcement running against whatever is already stored.
    std::vector<std::string> cloudrange_providers;
    // Addresses that are NEVER blocked, whatever the ranges say. external_admin/external_frontend
    // are added automatically — the frontend host is the source of essentially all legitimate
    // traffic, and it sits at a hosting provider, so without this the block would take the portal
    // offline. This is the equivalent of the frontend's exempt-IP allowlist short-circuit.
    std::vector<std::string> cloudrange_exempt_ips;

    /** True when `ip` is exempt from cloud-range blocking (admin, frontend, or configured). */
    bool cloudrange_exempt(const std::string& ip) const;

    // Paths that require the day-key on EVERY method, not just the write surface — the way to put a
    // read endpoint behind the rotating credential. Stored lower-case, leading '/', no trailing '/'.
    // Defaults to the assembled news home page, which is expensive to build and has no business
    // being scraped anonymously; ops can widen the list via CPROXY_DAYKEY_PATHS, or turn the path
    // gate off with CPROXY_DAYKEY_PATHS=NONE (an empty value would read as "unset" — see load_config).
    //
    // ALL THREE HOME-PAGE ENDPOINTS MUST BE LISTED TOGETHER. docapi 1.8.1 split /news/default into
    // /news/featured (the 2 lead articles, ~1.09 MB) and /news/more (the sidebar, ~1.6 KB); the three
    // serve the SAME content, so gating only /news/default leaves the other two as an unauthenticated
    // bypass around the gate — /news/featured alone hands over the whole expensive half. That was live
    // between the docapi 1.8.1 deploy and this change. If a future release splits or renames these
    // endpoints again, add the new paths HERE in the same commit.
    std::vector<std::string> daykey_paths = {"/news/default", "/news/featured", "/news/more"};

    /** Case-insensitive method allow-list check. Empty allow-list => everything permitted. */
    bool method_allowed(const std::string& method) const;

    /**
     * True when this request must present a valid X-Day-Guid: the whole write surface (POST/PATCH)
     * regardless of path, plus any path in daykey_paths regardless of method.
     */
    bool daykey_required(const std::string& method, const std::string& path) const;

    /** True when `path` is at or under one of the daykey_paths entries. */
    bool daykey_gated_path(const std::string& path) const;

    // Values typically supplied via an encrypted dotenv on the volume (EXTERNAL_ADMIN / EXTERNAL_FRONTEND);
    // decrypted at load time. Empty when not configured.
    std::string external_admin;     // e.g. an admin source IP (secret)
    std::string external_frontend;  // e.g. the frontend host

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
