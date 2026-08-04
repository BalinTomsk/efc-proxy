#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace cproxy {

namespace {

std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
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

Config load_config(const EnvLookup& env) {
    Config cfg;
    cfg.listen_addr = get_str(env, "CPROXY_LISTEN_ADDR", cfg.listen_addr);
    cfg.listen_port = get_int(env, "CPROXY_LISTEN_PORT", cfg.listen_port);
    cfg.docapi_upstream = get_str(env, "CPROXY_DOCAPI_UPSTREAM", cfg.docapi_upstream);
    cfg.route_prefix = get_str(env, "CPROXY_ROUTE_PREFIX", cfg.route_prefix);
    cfg.api_key = get_str(env, "CPROXY_API_KEY", cfg.api_key);
    cfg.connect_timeout_ms = get_int(env, "CPROXY_CONNECT_TIMEOUT_MS", cfg.connect_timeout_ms);
    cfg.read_timeout_ms = get_int(env, "CPROXY_READ_TIMEOUT_MS", cfg.read_timeout_ms);
    cfg.log_max_history = get_int(env, "CPROXY_LOG_MAX_HISTORY", cfg.log_max_history);
    cfg.external_admin = get_str(env, "EXTERNAL_ADMIN", cfg.external_admin);
    cfg.external_frontend = get_str(env, "EXTERNAL_FRONTEND", cfg.external_frontend);

    // log_dir is special: an explicitly-set but EMPTY value means "console only", so it is read
    // directly rather than via get_str (which would substitute the default for an empty value).
    if (auto ld = env("CPROXY_LOG_DIR")) {
        cfg.log_dir = trim(*ld);
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

}  // namespace cproxy
