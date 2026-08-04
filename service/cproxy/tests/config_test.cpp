// Minimal, framework-free unit tests for config parsing. Registered with CTest; run via
// `ctest --test-dir build` (also executed inside the Docker build).
#include <cassert>
#include <iostream>
#include <map>
#include <string>

#include "config.hpp"

using namespace cproxy;

namespace {

EnvLookup make_env(std::map<std::string, std::string> m) {
    return [m = std::move(m)](const char* key) -> std::optional<std::string> {
        auto it = m.find(key);
        if (it == m.end()) return std::nullopt;
        return it->second;
    };
}

void defaults_apply_when_env_is_empty() {
    Config c = load_config(make_env({}));
    assert(c.listen_addr == "0.0.0.0");
    assert(c.listen_port == 8080);
    assert(c.route_prefix == "/api/");
    // Default upstream is a neutral localhost placeholder — no real infrastructure address in tests.
    assert(c.docapi_upstream == "http://127.0.0.1:8080");
    assert(!c.auth_required());
    assert(c.method_allowed("GET"));
    assert(c.method_allowed("POST"));  // empty allow-list => all methods
    assert(c.log_dir == "logs");
    assert(c.log_max_history == 7);
}

void logging_env_is_read_including_empty_dir() {
    Config a = load_config(make_env({{"CPROXY_LOG_DIR", "/var/log/cproxy"},
                                     {"CPROXY_LOG_MAX_HISTORY", "14"}}));
    assert(a.log_dir == "/var/log/cproxy");
    assert(a.log_max_history == 14);
    // An explicitly-empty dir means console-only and must be honored (not replaced by the default).
    Config b = load_config(make_env({{"CPROXY_LOG_DIR", ""}}));
    assert(b.log_dir.empty());
}

void overrides_are_read_and_methods_restricted() {
    Config c = load_config(make_env({{"CPROXY_LISTEN_PORT", "9090"},
                                     {"CPROXY_DOCAPI_UPSTREAM", "http://10.0.0.5:8080"},
                                     {"CPROXY_API_KEY", "s3cret"},
                                     {"CPROXY_ALLOWED_METHODS", "GET, HEAD"}}));
    assert(c.listen_port == 9090);
    assert(c.docapi_upstream == "http://10.0.0.5:8080");
    assert(c.auth_required());
    assert(c.method_allowed("GET"));
    assert(c.method_allowed("get"));   // case-insensitive
    assert(c.method_allowed("HEAD"));
    assert(!c.method_allowed("POST"));  // not in the allow-list
}

void malformed_int_falls_back_and_all_keyword_means_unrestricted() {
    Config c = load_config(make_env({{"CPROXY_LISTEN_PORT", "not-a-number"},
                                     {"CPROXY_ALLOWED_METHODS", "ALL"}}));
    assert(c.listen_port == 8080);  // fell back to the default
    assert(c.method_allowed("DELETE"));
}

}  // namespace

int main() {
    defaults_apply_when_env_is_empty();
    overrides_are_read_and_methods_restricted();
    malformed_int_falls_back_and_all_keyword_means_unrestricted();
    logging_env_is_read_including_empty_dir();
    std::cout << "config_test: all assertions passed\n";
    return 0;
}
