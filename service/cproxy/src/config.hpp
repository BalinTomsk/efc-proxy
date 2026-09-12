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
 * | CPROXY_DAYKEY_DB            | (empty)                       | path to the day-key SQLite db; every gated request 500s while empty |
 * | CPROXY_DAYKEY_PATHS         | /news/default,/news/featured,/news/more,/news/photo | CSV of paths gated on EVERY method, GET included ("NONE" disables) |
 * | CPROXY_JWT_SECRET           | (empty)                       | HS512 shared secret; empty = every gated request 500s (no other credential exists) |
 * | CPROXY_JWT_REQUIRE_USER     | false                         | true = writes must name an account, and any `user` claim must match the mirror |
 * | CPROXY_JWT_ISSUER           | envfish                       | required `iss` ("" = do not check)        |
 * | CPROXY_JWT_AUDIENCE         | fishfind.info                 | required `aud` ("" = do not check)        |
 * | CPROXY_JWT_SUBJECT          | cproxy                        | required `sub` ("" = do not check)        |
 * | CPROXY_JWT_LEEWAY_SECONDS   | 300                           | clock-skew allowance on exp/iat           |
 * | CPROXY_JWT_USER_CACHE_SECONDS | 60                          | how long the account-prime snapshot is reused |
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

    // Path to the day-key SQLite database (see DayKeyStore). Empty means the day-key cannot be
    // checked, so every gated request fails closed with 500 regardless of CPROXY_ALLOWED_METHODS.
    std::string daykey_db_path;

    // --- JWT credential (0.10.0; the only credential since 0.13.0) ----------------------------
    // Callers present `Authorization: Bearer <HS512 JWT>`. The token's `server` claim carries the
    // day-key (DayKeyStore stays the authority on it) and its `user` claim carries
    // Users.prime * Users_Prime.prime for today, which UserPrimeStore re-derives from the account
    // mirror. See jwt_verifier.hpp.
    //
    // Shared HS512 secret, matching the frontend's FishApi:JwtKey. EMPTY SHUTS THE GATED SURFACE:
    // with nothing to verify a token against, every POST/PATCH and every CPROXY_DAYKEY_PATHS read
    // answers 500. There is no fallback credential — the raw X-Day-Guid header, and the
    // CPROXY_JWT_REQUIRED switch that used to decide whether it was still honoured, were removed in
    // 0.13.0. A leftover CPROXY_JWT_REQUIRED in the environment is ignored (main logs a WARN).
    std::string jwt_secret;
    // When true, a `user` claim is REQUIRED on every write (POST/PATCH) and, wherever one is
    // present, must resolve to a live, non-suspended, non-deleted account in the mirror. A gated
    // READ may still be anonymous — /news/featured and /news/more are the public home page, and the
    // gate on them exists to stop anonymous scraping, not anonymous reading.
    //
    // Default false because the mirror is fed by the RabbitMQ users-sync pipeline: turning this on
    // against an unpopulated mirror refuses every write and every signed-in visitor's reads. Turn it
    // on only once the mirror is known to be current (the startup log reports how many accounts it
    // loaded).
    bool jwt_require_user = false;
    // Claims the token must carry, "" meaning "do not check". Defaults match the platform's minter
    // (fishfind-frontend/doc/envfish-jwt.html).
    std::string jwt_issuer = "envfish";
    std::string jwt_audience = "fishfind.info";
    std::string jwt_subject = "cproxy";
    // Clock-skew allowance on exp/iat, seconds. The token lives one day; a few minutes of slack
    // between two independently-clocked hosts costs nothing.
    int jwt_leeway_seconds = 300;
    // How long a UserPrimeStore snapshot is reused before it is rebuilt from the mirror. A
    // suspension or deletion takes at most this long to bite.
    int jwt_user_cache_seconds = 60;

    // --- Clock alignment from an admin token (see ClockOffset) ---
    // Lets cproxy correct its own notion of "now" (for credential validation ONLY, never the system
    // clock) from a request carrying both an admin ACCOUNT's token and an X-Client-Time header.
    // "Admin" is looked up in the account mirror (users_sync.access == 255) by the token's `user`
    // product -- never read from the token (0.12.0; see UserPrimeStore::is_admin).
    //
    // Default true is safe by construction rather than by trust: it is inert unless the mirror holds
    // a live superAdmin whose token arrives with the header. Setting it true also makes cproxy open
    // the mirror even when CPROXY_JWT_REQUIRE_USER is off. Set false to pin cproxy to its host clock
    // permanently.
    bool jwt_clock_sync = true;
    // Don't correct below this. Sub-threshold gaps are network latency and the one-second
    // granularity of an epoch header, not drift, and chasing them would rewrite the offset on every
    // admin request for no gain.
    int jwt_clock_sync_threshold_seconds = 5;
    // Ceiling on the TOTAL offset, in either direction. This is the security bound on the feature:
    // a replayed admin token cannot move cproxy more than this, which is why an hour is the default
    // and a day is not — a captured token would need ~24h to make its stale day-key current again,
    // and anything under a day is already inside DayKeyStore's own +/-1-day window.
    int jwt_clock_sync_max_seconds = 3600;

    /** True when CPROXY_JWT_SECRET is set, i.e. the gated surface can be opened at all. */
    bool jwt_enabled() const { return !jwt_secret.empty(); }

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

    // RabbitMQ account-event consumer. When enabled, cproxy polls the RabbitMQ management HTTPS API
    // for account/user and API-key events emitted by fishfind-frontend, then mirrors them into a
    // local SQLite database for fast local auth/cache use.
    bool rabbitmq_events_enabled = false;
    // No real infrastructure address baked in as a default (same reason docapi_upstream stays a
    // neutral placeholder): production always sets CPROXY_RABBITMQ_MANAGEMENT_URL explicitly, and
    // validate_config() fails startup on an empty/schemeless value when events are enabled.
    std::string rabbitmq_management_url;
    std::string rabbitmq_username = "fishfind";
    std::string rabbitmq_password;
    std::string rabbitmq_queue = "fishfind.account.events";
    std::string account_mirror_db_path = "/var/lib/cproxy/auth.sqlite";
    int rabbitmq_poll_ms = 1000;
    int rabbitmq_batch_size = 25;

    /** True when `ip` is exempt from cloud-range blocking (admin, frontend, or configured). */
    bool cloudrange_exempt(const std::string& ip) const;

    // Paths that require the day-key on EVERY method, not just the write surface — the way to put a
    // read endpoint behind the rotating credential. Stored lower-case, leading '/', no trailing '/'.
    // Defaults to the assembled news home page, which is expensive to build and has no business
    // being scraped anonymously; ops can widen the list via CPROXY_DAYKEY_PATHS, or turn the path
    // gate off with CPROXY_DAYKEY_PATHS=NONE (an empty value would read as "unset" — see load_config).
    //
    // ALL THE HOME-PAGE ENDPOINTS MUST BE LISTED TOGETHER. docapi 1.8.1 split /news/default into
    // /news/featured (the 2 lead articles, ~1.09 MB) and /news/more (the sidebar, ~1.6 KB); the three
    // serve the SAME content, so gating only /news/default leaves the other two as an unauthenticated
    // bypass around the gate — /news/featured alone hands over the whole expensive half. That was live
    // between the docapi 1.8.1 deploy and this change. If a future release splits or renames these
    // endpoints again, add the new paths HERE in the same commit.
    //
    // /news/photo (docapi 1.9.0) is the fourth: the lead photos that /news/featured embeds as base64,
    // served by id as raw bytes so the frontend needs no MySQL connection of its own. Same content,
    // so leaving it open would be the same bypass one more time — the entry's trailing segment is the
    // article id, which the contains() arm of daykey_gated_path covers.
    std::vector<std::string> daykey_paths = {"/news/default", "/news/featured", "/news/more", "/news/photo"};

    /** Case-insensitive method allow-list check. Empty allow-list => everything permitted. */
    bool method_allowed(const std::string& method) const;

    /**
     * True when this request must present the gateway credential (a Bearer JWT carrying the day-key):
     * the whole write surface (POST/PATCH) regardless of path, plus any path in daykey_paths
     * regardless of method.
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
 *
 * Deliberately covers ONLY what the proxy itself needs. Settings that belong to an optional
 * side-feature are checked by their own function (see rabbitmq_config_problems) so a broken feature
 * degrades instead of taking the whole service down.
 */
std::vector<std::string> validate_config(const Config& cfg);

/**
 * Problems that disable ONLY the RabbitMQ account/user mirror, never the proxy. Empty when events
 * are disabled, or when they are enabled and fully configured.
 *
 * Separate from validate_config on purpose: forwarding /api/* does not depend on the mirror, so a
 * missing management URL or password must not stop cproxy from binding its port. Treating these as
 * fatal took the public edge offline on the 0.9.2 deploy. main() logs each problem and turns the
 * consumer off instead.
 */
std::vector<std::string> rabbitmq_config_problems(const Config& cfg);

}  // namespace cproxy

