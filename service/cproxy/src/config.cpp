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

std::string normalize_gate_path(std::string s) {
    s = to_lower(trim(s));
    if (s.empty()) return s;
    if (s.front() != '/') s.insert(s.begin(), '/');
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
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
    if (daykey_paths.empty()) return false;
    const std::string norm = normalize_gate_path(path);
    for (const std::string& entry : daykey_paths) {
        // ends_with covers the endpoint itself at any route prefix ("/api/v1" + "/news/default");
        // the entry's own leading '/' is what keeps it on a segment boundary, so "/oldnews/default"
        // does not match "/news/default". The contains() arm extends the gate to anything nested
        // under a gated path - a sub-resource of a protected resource is protected too.
        if (norm.ends_with(entry) || norm.contains(entry + "/")) return true;
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
    return errors;
}

}  // namespace cproxy
