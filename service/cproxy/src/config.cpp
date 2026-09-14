#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace cproxy {

// Defined in cloud_range_refresh.cpp. Forward-declared rather than included: that header pulls in
// httplib/json and depends on this one, so including it here would be circular.
std::vector<std::string> known_cloud_providers();

namespace {

std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

std::string get_str(const EnvLookup& env, const char* name, const std::string& fallback) {
    auto v = env(name);
    if (!v || trim(*v).empty()) return fallback;
    return trim(*v);
}

int get_int(const EnvLookup& env, const char* name, int fallback) {
    auto v = env(name);
    if (!v) return fallback;
    try {
        return std::stoi(trim(*v));
    } catch (...) {
        return fallback;  // malformed value falls back rather than crashing the service
    }
}

/**
 * Canonical form for day-key path matching: lower-cased, guaranteed leading '/', trailing '/'
 * stripped. Applied to BOTH the configured entries and the incoming request path so that
 * "/News/Default/" and "/news/default" cannot be two different things to the gate.
 *
 * Case folding is deliberate even though HTTP paths are case-sensitive: the cost of gating a
 * request the upstream would have 404'd is nothing, while the cost of letting "/News/Default"
 * through on an upstream that happens to route case-insensitively is the whole point of the gate.
 */
/** Parses a CSV env value into trimmed, non-empty tokens. */
std::vector<std::string> split_csv(const std::string& value) {
    std::vector<std::string> out;
    std::istringstream ss(value);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        auto t = trim(tok);
        if (!t.empty()) out.push_back(t);
    }
    return out;
}

/** "false"/"0"/"no"/"off" are false; anything else keeps the default. Mirrors the frontend's
 *  true/`false`/`0` appSetting convention for BlockCloudProviderIps. */
bool get_bool(const EnvLookup& env, const char* name, bool fallback) {
    auto v = env(name);
    if (!v || trim(*v).empty()) return fallback;
    const std::string s = to_upper(trim(*v));
    if (s == "FALSE" || s == "0" || s == "NO" || s == "OFF") return false;
    if (s == "TRUE" || s == "1" || s == "YES" || s == "ON") return true;
    return fallback;
}

/** The "NONE" off-sentinel, shared by the three JWT claim checks. See load_config for why the off
 *  switch cannot be an empty string. */
std::string none_to_empty(const std::string& value) {
    return to_upper(value) == "NONE" ? std::string{} : value;
}

std::string normalize_gate_path(std::string s) {
    s = to_lower(trim(s));
    if (s.empty()) return s;
    if (s.front() != '/') s.insert(s.begin(), '/');
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

/**
 * Whether one path segment has the shape of a document id: a canonical 8-4-4-4-12 hex GUID, which
 * is what docapi uses for every entity key it exposes by id.
 *
 * Deliberately STRICT. A false positive here gates something cheap — harmless but confusing; a
 * false NEGATIVE leaves a megabyte-scale endpoint open, which is the bug this rule exists to close.
 * Strictness is nonetheless the right trade because the thing being told apart is a guid from an
 * English word (`list`, `search`, `default`, `featured`, `more`, `photo`, `export`, `import`), and no
 * word is 36 characters of hex and dashes. The input is already lower-cased by normalize_gate_path,
 * so only lower-case hex is accepted — do not "fix" that by adding A-F unless the normalizer changes.
 *
 * A bare 32-hex (unhyphenated) form is NOT accepted: docapi has never emitted or accepted one, and
 * admitting it would widen the rule on speculation rather than on a route that exists.
 */
bool looks_like_document_id(const std::string& seg) {
    static constexpr std::size_t kGuidLength = 36;
    if (seg.size() != kGuidLength) return false;
    for (std::size_t i = 0; i < kGuidLength; ++i) {
        const char c = seg[i];
        const bool dash_position = (i == 8 || i == 13 || i == 18 || i == 23);
        if (dash_position) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::optional<std::string> system_env(const char* name) {
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') return std::nullopt;
    return std::string(v);
}

bool Config::method_allowed(const std::string& method) const {
    if (allowed_methods.empty()) return true;
    return allowed_methods.count(to_upper(method)) > 0;
}

bool Config::daykey_gated_path(const std::string& path) const {
    // The two lists are INDEPENDENT switches. This deliberately does not early-return on an empty
    // daykey_paths: CPROXY_DAYKEY_PATHS=NONE must turn off the tail gate only, not silently take the
    // document-id gate with it. Turning that one off is CPROXY_DAYKEY_ID_PATHS=NONE.
    const std::string norm = normalize_gate_path(path);
    for (const std::string& entry : daykey_paths) {
        // ends_with covers the endpoint itself at any route prefix ("/api/v1" + "/news/default");
        // the entry's own leading '/' is what keeps it on a segment boundary, so "/oldnews/default"
        // does not match "/news/default". The contains() arm extends the gate to anything nested
        // under a gated path - a sub-resource of a protected resource is protected too.
        if (norm.ends_with(entry) || norm.contains(entry + "/")) return true;
    }
    return daykey_gated_id_path(path);
}

bool Config::daykey_gated_id_path(const std::string& path) const {
    if (daykey_id_paths.empty()) return false;
    const std::string norm = normalize_gate_path(path);

    // Split the last segment off. normalize_gate_path has already stripped any trailing slash, so
    // the last segment is never empty here.
    const std::size_t slash = norm.rfind('/');
    if (slash == std::string::npos || slash == 0) return false;
    if (!looks_like_document_id(norm.substr(slash + 1))) return false;

    // The parent must END WITH the entry, not merely contain it: that keeps the rule on a segment
    // boundary and at the right depth, so "/news/<guid>" is gated while "/news/export/<guid>"
    // (parent "/news/export") is not caught HERE — it is already gated as a literal daykey_paths
    // entry, and matching it twice would only obscure which rule is doing the work.
    const std::string parent = norm.substr(0, slash);
    for (const std::string& entry : daykey_id_paths) {
        if (parent.ends_with(entry)) return true;
    }
    return false;
}

bool Config::cloudrange_exempt(const std::string& ip) const {
    if (ip.empty()) return false;
    // The frontend host and the admin address are exempt unconditionally. Both are ordinary
    // hosting/ISP addresses that a provider feed can legitimately cover, and blocking either would
    // take the portal (or our own access to it) down — the same reason the frontend's allowlist
    // short-circuits before any block check.
    if (!external_frontend.empty() && ip == external_frontend) return true;
    if (!external_admin.empty() && ip == external_admin) return true;
    return std::find(cloudrange_exempt_ips.begin(), cloudrange_exempt_ips.end(), ip) !=
           cloudrange_exempt_ips.end();
}

bool Config::daykey_required(const std::string& method, const std::string& path) const {
    // The write surface is gated wholesale, whatever the path (see proxy_to_docapi).
    const std::string m = to_upper(method);
    if (m == "POST" || m == "PATCH") return true;
    return daykey_gated_path(path);
}

Config load_config(const EnvLookup& env) {
    Config cfg;
    cfg.listen_addr = get_str(env, "CPROXY_LISTEN_ADDR", cfg.listen_addr);
    cfg.listen_port = get_int(env, "CPROXY_LISTEN_PORT", cfg.listen_port);
    cfg.docapi_upstream = get_str(env, "CPROXY_DOCAPI_UPSTREAM", cfg.docapi_upstream);
    cfg.route_prefix = get_str(env, "CPROXY_ROUTE_PREFIX", cfg.route_prefix);
    cfg.api_key = get_str(env, "CPROXY_API_KEY", cfg.api_key);
    cfg.connect_timeout_ms = get_int(env, "CPROXY_CONNECT_TIMEOUT_MS", cfg.connect_timeout_ms);
    cfg.read_timeout_ms = get_int(env, "CPROXY_READ_TIMEOUT_MS", cfg.read_timeout_ms);
    cfg.max_payload_bytes = get_int(env, "CPROXY_MAX_PAYLOAD_BYTES", cfg.max_payload_bytes);
    cfg.breaker_threshold = get_int(env, "CPROXY_BREAKER_THRESHOLD", cfg.breaker_threshold);
    cfg.breaker_cooldown_ms = get_int(env, "CPROXY_BREAKER_COOLDOWN_MS", cfg.breaker_cooldown_ms);
    cfg.upstream_retry = get_int(env, "CPROXY_UPSTREAM_RETRY", cfg.upstream_retry);
    cfg.log_max_history = get_int(env, "CPROXY_LOG_MAX_HISTORY", cfg.log_max_history);
    cfg.daykey_db_path = get_str(env, "CPROXY_DAYKEY_DB", cfg.daykey_db_path);
    cfg.external_admin = get_str(env, "EXTERNAL_ADMIN", cfg.external_admin);
    cfg.external_frontend = get_str(env, "EXTERNAL_FRONTEND", cfg.external_frontend);

    // --- JWT credential -----------------------------------------------------------------------
    // The secret is typically an enc:v1: value in the dotenv (see secret_codec), so it arrives here
    // already decrypted. Empty shuts the gated surface (there is no other credential). The retired
    // CPROXY_JWT_REQUIRED is deliberately not read: no value of it can bring X-Day-Guid back.
    cfg.jwt_secret = get_str(env, "CPROXY_JWT_SECRET", cfg.jwt_secret);
    cfg.jwt_require_user = get_bool(env, "CPROXY_JWT_REQUIRE_USER", cfg.jwt_require_user);
    cfg.jwt_leeway_seconds = get_int(env, "CPROXY_JWT_LEEWAY_SECONDS", cfg.jwt_leeway_seconds);
    cfg.jwt_user_cache_seconds =
        get_int(env, "CPROXY_JWT_USER_CACHE_SECONDS", cfg.jwt_user_cache_seconds);
    cfg.jwt_clock_sync = get_bool(env, "CPROXY_JWT_CLOCK_SYNC", cfg.jwt_clock_sync);
    cfg.jwt_clock_sync_threshold_seconds = get_int(
        env, "CPROXY_JWT_CLOCK_SYNC_THRESHOLD_SECONDS", cfg.jwt_clock_sync_threshold_seconds);
    cfg.jwt_clock_sync_max_seconds =
        get_int(env, "CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS", cfg.jwt_clock_sync_max_seconds);
    // "NONE" switches an individual claim check off. A sentinel again rather than "": system_env
    // reports an empty variable as unset, so CPROXY_JWT_ISSUER= would silently leave the default
    // "envfish" requirement standing — the opposite of what an operator typing it means.
    cfg.jwt_issuer = none_to_empty(get_str(env, "CPROXY_JWT_ISSUER", cfg.jwt_issuer));
    cfg.jwt_audience = none_to_empty(get_str(env, "CPROXY_JWT_AUDIENCE", cfg.jwt_audience));
    cfg.jwt_subject = none_to_empty(get_str(env, "CPROXY_JWT_SUBJECT", cfg.jwt_subject));

    // "NONE" turns file logging off (console only); anything else is the rolling-log directory.
    // The off switch is a sentinel rather than an empty string for the same reason as
    // CPROXY_DAYKEY_PATHS below: system_env() reports an empty variable as unset, so through a real
    // process environment `-e CPROXY_LOG_DIR=` is indistinguishable from not setting it at all and
    // can only ever mean "use the default". This used to be read directly (empty => console only),
    // which worked in the unit tests and from a dotenv line but never from the documented `-e` form
    // — see console_only_sentinel_works_through_the_real_environment in config_test.
    auto log_dir = get_str(env, "CPROXY_LOG_DIR", cfg.log_dir);
    cfg.log_dir = to_upper(log_dir) == "NONE" ? "" : log_dir;

    // "NONE" turns the path gate off entirely; anything else is a CSV that REPLACES the default.
    // The off switch is a sentinel rather than an empty string because system_env() reports an
    // empty variable as unset, so CPROXY_DAYKEY_PATHS="" is indistinguishable from not setting it
    // at all and would silently leave the default gate in place — the opposite of what an operator
    // typing it means. (Same reason CPROXY_ALLOWED_METHODS spells "no restriction" as "ALL".)
    if (auto paths = env("CPROXY_DAYKEY_PATHS")) {
        cfg.daykey_paths.clear();
        if (to_upper(trim(*paths)) != "NONE") {
            std::istringstream ps(*paths);
            std::string ptok;
            while (std::getline(ps, ptok, ',')) {
                auto p = normalize_gate_path(ptok);
                if (!p.empty() && p != "/") cfg.daykey_paths.push_back(p);
            }
        }
    }

    // Same CSV-replaces / NONE-disables contract as CPROXY_DAYKEY_PATHS above, for the same
    // reason (system_env reports an empty variable as unset).
    if (auto id_paths = env("CPROXY_DAYKEY_ID_PATHS")) {
        cfg.daykey_id_paths.clear();
        if (to_upper(trim(*id_paths)) != "NONE") {
            std::istringstream ips(*id_paths);
            std::string itok;
            while (std::getline(ips, itok, ',')) {
                auto p = normalize_gate_path(itok);
                if (!p.empty() && p != "/") cfg.daykey_id_paths.push_back(p);
            }
        }
    }

    // --- Datacenter / cloud-provider blocking -------------------------------------------------
    cfg.cloudrange_db_path = get_str(env, "CPROXY_CLOUDRANGE_DB", cfg.cloudrange_db_path);
    cfg.cloudrange_block_enabled =
        get_bool(env, "CPROXY_BLOCK_CLOUD_IPS", cfg.cloudrange_block_enabled);
    cfg.cloudrange_refresh_hours =
        get_int(env, "CPROXY_CLOUDRANGE_REFRESH_HOURS", cfg.cloudrange_refresh_hours);
    cfg.cloudrange_refresh_on_start =
        get_bool(env, "CPROXY_CLOUDRANGE_REFRESH_ON_START", cfg.cloudrange_refresh_on_start);
    cfg.cloudrange_fetch_timeout_seconds =
        get_int(env, "CPROXY_CLOUDRANGE_FETCH_TIMEOUT_SECONDS",
                cfg.cloudrange_fetch_timeout_seconds);
    cfg.cloudrange_exempt_ips = split_csv(get_str(env, "CPROXY_CLOUDRANGE_EXEMPT_IPS", ""));

    cfg.rabbitmq_events_enabled =
        get_bool(env, "CPROXY_RABBITMQ_EVENTS_ENABLED", cfg.rabbitmq_events_enabled);
    cfg.rabbitmq_management_url =
        get_str(env, "CPROXY_RABBITMQ_MANAGEMENT_URL", cfg.rabbitmq_management_url);
    cfg.rabbitmq_username = get_str(env, "CPROXY_RABBITMQ_USERNAME", cfg.rabbitmq_username);
    cfg.rabbitmq_password = get_str(env, "CPROXY_RABBITMQ_PASSWORD", cfg.rabbitmq_password);
    cfg.rabbitmq_queue = get_str(env, "CPROXY_RABBITMQ_QUEUE", cfg.rabbitmq_queue);
    cfg.account_mirror_db_path =
        get_str(env, "CPROXY_ACCOUNT_MIRROR_DB", cfg.account_mirror_db_path);
    cfg.rabbitmq_poll_ms = get_int(env, "CPROXY_RABBITMQ_POLL_MS", cfg.rabbitmq_poll_ms);
    cfg.rabbitmq_batch_size = get_int(env, "CPROXY_RABBITMQ_BATCH_SIZE", cfg.rabbitmq_batch_size);

    // Unset => every feed this build knows. "NONE" stops the refresh without disabling enforcement,
    // so the stored ranges keep blocking while the fetching is paused. (Sentinel, not "", for the
    // reason spelled out above CPROXY_LOG_DIR.)
    {
        auto providers = get_str(env, "CPROXY_CLOUDRANGE_PROVIDERS", "");
        if (providers.empty()) {
            cfg.cloudrange_providers = known_cloud_providers();
        } else if (to_upper(providers) != "NONE") {
            cfg.cloudrange_providers = split_csv(providers);
        }
    }

    // "ALL" or empty means no restriction; anything else is a CSV allow-list.
    auto methods = get_str(env, "CPROXY_ALLOWED_METHODS", "");
    if (!methods.empty() && to_upper(methods) != "ALL") {
        std::istringstream ss(methods);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            auto t = trim(tok);
            if (!t.empty()) cfg.allowed_methods.insert(to_upper(t));
        }
    }
    return cfg;
}

std::vector<std::string> rabbitmq_config_problems(const Config& cfg) {
    std::vector<std::string> problems;
    if (!cfg.rabbitmq_events_enabled) return problems;  // nothing to run, nothing to complain about

    if (cfg.rabbitmq_management_url.rfind("http://", 0) != 0 &&
        cfg.rabbitmq_management_url.rfind("https://", 0) != 0)
        problems.push_back("CPROXY_RABBITMQ_MANAGEMENT_URL must be scheme://host[:port] with http or https");
    if (cfg.rabbitmq_username.empty())
        problems.push_back("CPROXY_RABBITMQ_USERNAME is required when RabbitMQ events are enabled");
    if (cfg.rabbitmq_password.empty())
        problems.push_back("CPROXY_RABBITMQ_PASSWORD is required when RabbitMQ events are enabled");
    if (cfg.rabbitmq_queue.empty())
        problems.push_back("CPROXY_RABBITMQ_QUEUE is required when RabbitMQ events are enabled");
    if (cfg.account_mirror_db_path.empty())
        problems.push_back("CPROXY_ACCOUNT_MIRROR_DB is required when RabbitMQ events are enabled");
    if (cfg.rabbitmq_poll_ms <= 0)
        problems.push_back("CPROXY_RABBITMQ_POLL_MS must be positive");
    if (cfg.rabbitmq_batch_size <= 0)
        problems.push_back("CPROXY_RABBITMQ_BATCH_SIZE must be positive");
    return problems;
}

std::vector<std::string> validate_config(const Config& cfg) {
    std::vector<std::string> errors;
    if (cfg.listen_port < 1 || cfg.listen_port > 65535)
        errors.push_back("CPROXY_LISTEN_PORT must be 1-65535");
    if (cfg.connect_timeout_ms <= 0)
        errors.push_back("CPROXY_CONNECT_TIMEOUT_MS must be positive");
    if (cfg.read_timeout_ms <= 0)
        errors.push_back("CPROXY_READ_TIMEOUT_MS must be positive");
    if (cfg.max_payload_bytes <= 0)
        errors.push_back("CPROXY_MAX_PAYLOAD_BYTES must be positive");
    if (cfg.breaker_threshold < 0)
        errors.push_back("CPROXY_BREAKER_THRESHOLD must be >= 0 (0 disables the breaker)");
    if (cfg.breaker_cooldown_ms < 0)
        errors.push_back("CPROXY_BREAKER_COOLDOWN_MS must be >= 0");
    if (cfg.upstream_retry < 0)
        errors.push_back("CPROXY_UPSTREAM_RETRY must be >= 0 (0 disables retries)");
    if (cfg.route_prefix.empty() || cfg.route_prefix.front() != '/')
        errors.push_back("CPROXY_ROUTE_PREFIX must start with '/'");
    if (cfg.docapi_upstream.rfind("http://", 0) != 0 && cfg.docapi_upstream.rfind("https://", 0) != 0)
        errors.push_back("CPROXY_DOCAPI_UPSTREAM must be scheme://host[:port] with http or https");
    if (cfg.jwt_leeway_seconds < 0)
        errors.push_back("CPROXY_JWT_LEEWAY_SECONDS must be >= 0");
    if (cfg.jwt_user_cache_seconds <= 0)
        errors.push_back("CPROXY_JWT_USER_CACHE_SECONDS must be positive");
    if (cfg.jwt_clock_sync_threshold_seconds < 1)
        errors.push_back("CPROXY_JWT_CLOCK_SYNC_THRESHOLD_SECONDS must be >= 1");
    if (cfg.jwt_clock_sync_max_seconds < 0)
        errors.push_back("CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS must be >= 0 (0 pins the host clock)");
    // A ceiling below the trigger point could never be reached, so the feature would look enabled
    // and silently never correct anything. Refuse the combination rather than ship that puzzle.
    if (cfg.jwt_clock_sync && cfg.jwt_clock_sync_max_seconds < cfg.jwt_clock_sync_threshold_seconds)
        errors.push_back(
            "CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS must be >= CPROXY_JWT_CLOCK_SYNC_THRESHOLD_SECONDS");
    // Fatal rather than a warning: an operator who asked for account checks on tokens but gave no
    // secret to verify tokens with has a config that cannot mean what they intended.
    //
    // A missing secret on its own is NOT fatal: it shuts only the gated surface (every gated request
    // 500s, like a missing day-key store) while the ungated GET surface keeps serving. main() logs it
    // at ERROR. Refusing to start would turn a credential mistake into a whole-edge outage.
    if (cfg.jwt_require_user && !cfg.jwt_enabled())
        errors.push_back("CPROXY_JWT_REQUIRE_USER needs CPROXY_JWT_SECRET to be set");
    if (cfg.jwt_require_user && cfg.account_mirror_db_path.empty())
        errors.push_back("CPROXY_JWT_REQUIRE_USER needs CPROXY_ACCOUNT_MIRROR_DB to be set");
    // RabbitMQ settings are deliberately NOT checked here — see rabbitmq_config_problems().
    return errors;
}

}  // namespace cproxy

