// Minimal, framework-free unit tests for config parsing. Registered with CTest; run via
// `ctest --test-dir build` (also executed inside the Docker build).
#include "check.hpp"
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
    CHECK(c.listen_addr == "0.0.0.0");
    CHECK(c.listen_port == 8080);
    CHECK(c.route_prefix == "/api/");
    // Default upstream is a neutral localhost placeholder — no real infrastructure address in tests.
    CHECK(c.docapi_upstream == "http://127.0.0.1:8080");
    CHECK(!c.auth_required());
    CHECK(c.method_allowed("GET"));
    CHECK(c.method_allowed("POST"));  // empty allow-list => all methods
    CHECK(c.log_dir == "logs");
    CHECK(c.log_max_history == 7);
    CHECK(c.external_admin.empty());
    CHECK(c.external_frontend.empty());
}

void external_values_are_read_from_the_env_lookup() {
    // In production these arrive decrypted from the dotenv; here the lookup supplies them directly.
    Config c = load_config(make_env({{"EXTERNAL_ADMIN", "203.0.113.7"},
                                     {"EXTERNAL_FRONTEND", "example.test"}}));
    CHECK(c.external_admin == "203.0.113.7");
    CHECK(c.external_frontend == "example.test");
}

void logging_env_is_read_including_empty_dir() {
    Config a = load_config(make_env({{"CPROXY_LOG_DIR", "/var/log/cproxy"},
                                     {"CPROXY_LOG_MAX_HISTORY", "14"}}));
    CHECK(a.log_dir == "/var/log/cproxy");
    CHECK(a.log_max_history == 14);
    // An explicitly-empty dir means console-only and must be honored (not replaced by the default).
    Config b = load_config(make_env({{"CPROXY_LOG_DIR", ""}}));
    CHECK(b.log_dir.empty());
}

void overrides_are_read_and_methods_restricted() {
    Config c = load_config(make_env({{"CPROXY_LISTEN_PORT", "9090"},
                                     {"CPROXY_DOCAPI_UPSTREAM", "http://10.0.0.5:8080"},
                                     {"CPROXY_API_KEY", "s3cret"},
                                     {"CPROXY_ALLOWED_METHODS", "GET, HEAD"}}));
    CHECK(c.listen_port == 9090);
    CHECK(c.docapi_upstream == "http://10.0.0.5:8080");
    CHECK(c.auth_required());
    CHECK(c.method_allowed("GET"));
    CHECK(c.method_allowed("get"));   // case-insensitive
    CHECK(c.method_allowed("HEAD"));
    CHECK(!c.method_allowed("POST"));  // not in the allow-list
}

void malformed_int_falls_back_and_all_keyword_means_unrestricted() {
    Config c = load_config(make_env({{"CPROXY_LISTEN_PORT", "not-a-number"},
                                     {"CPROXY_ALLOWED_METHODS", "ALL"}}));
    CHECK(c.listen_port == 8080);  // fell back to the default
    CHECK(c.method_allowed("DELETE"));
}

void validation_accepts_defaults_and_rejects_nonsense() {
    // The untouched default config must always validate clean.
    CHECK(validate_config(load_config(make_env({}))).empty());

    Config bad = load_config(make_env({}));
    bad.listen_port = 0;
    bad.connect_timeout_ms = -1;
    bad.read_timeout_ms = 0;
    bad.max_payload_bytes = 0;
    bad.route_prefix = "api/";                 // missing leading '/'
    bad.docapi_upstream = "10.0.0.5:8080";     // missing scheme
    CHECK(validate_config(bad).size() == 6);   // one message per problem
}

void payload_limit_is_read_with_default() {
    CHECK(load_config(make_env({})).max_payload_bytes == 1 * 1024 * 1024);
    Config c = load_config(make_env({{"CPROXY_MAX_PAYLOAD_BYTES", "2048"}}));
    CHECK(c.max_payload_bytes == 2048);
}

}  // namespace

int main() {
    defaults_apply_when_env_is_empty();
    overrides_are_read_and_methods_restricted();
    malformed_int_falls_back_and_all_keyword_means_unrestricted();
    logging_env_is_read_including_empty_dir();
    external_values_are_read_from_the_env_lookup();
    validation_accepts_defaults_and_rejects_nonsense();
    payload_limit_is_read_with_default();
    std::cout << "config_test: all assertions passed\n";
    return 0;
}
