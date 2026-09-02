// Minimal, framework-free unit tests for config parsing. Registered with CTest; run via
// `ctest --test-dir build` (also executed inside the Docker build).
#include "check.hpp"
#include <cstdlib>  // setenv/unsetenv (POSIX), _putenv_s (Windows) — see put_real_env
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

void logging_env_is_read_including_console_only_sentinel() {
    Config a = load_config(make_env({{"CPROXY_LOG_DIR", "/var/log/cproxy"},
                                     {"CPROXY_LOG_MAX_HISTORY", "14"}}));
    CHECK(a.log_dir == "/var/log/cproxy");
    CHECK(a.log_max_history == 14);
    // "NONE" is the console-only switch, and it must survive the casing/padding an operator types.
    for (const char* off_value : {"NONE", "none", " None "}) {
        CHECK(load_config(make_env({{"CPROXY_LOG_DIR", off_value}})).log_dir.empty());
    }
    // An empty value is NOT the switch: it reads as unset and leaves the default standing. Asserted
    // here for the contract, and through the real process environment below for the reason.
    CHECK(load_config(make_env({{"CPROXY_LOG_DIR", ""}})).log_dir == "logs");
}

/**
 * Sets `name` in the REAL process environment; a null `value` removes it. Windows and POSIX disagree
 * about what an explicitly-empty variable even is — POSIX keeps it as an empty string, Windows
 * deletes it — which is part of why "explicitly empty" cannot be a portable config state.
 */
void put_real_env(const char* name, const char* value) {
#ifdef _WIN32
    _putenv_s(name, value == nullptr ? "" : value);
#else
    if (value == nullptr) {
        ::unsetenv(name);
    } else {
        ::setenv(name, value, 1);
    }
#endif
}

/**
 * The trap this pins down: system_env() maps an explicitly-EMPTY variable to nullopt, so through a
 * real process environment `-e CPROXY_LOG_DIR=` cannot mean anything other than "unset".
 *
 * Every assertion here goes through the real environment and the real system_env, NOT make_env —
 * the fake hands back a genuine empty string that the process environment never produces, and that
 * gap is exactly what let CPROXY_LOG_DIR="" be documented as a working console-only switch (and
 * unit-tested as one) while the deployed service silently kept writing rolling files. The same blind
 * spot bit CPROXY_DAYKEY_PATHS in 0.7.0.
 */
void console_only_sentinel_works_through_the_real_environment() {
    // The blind spot itself, turned into an assertion: the fake and the real environment do NOT
    // agree about what an explicitly-empty variable is, so any config rule that leans on "empty"
    // has to be validated against the real one before it can be documented as working.
    put_real_env("CPROXY_LOG_DIR", "");
    CHECK(make_env({{"CPROXY_LOG_DIR", ""}})("CPROXY_LOG_DIR").has_value());  // fake: a real ""
    CHECK(!system_env("CPROXY_LOG_DIR").has_value());  // reality: indistinguishable from unset ...
    CHECK(load_config().log_dir == "logs");            // ... so the default has to stand

    put_real_env("CPROXY_LOG_DIR", "NONE");
    auto v = system_env("CPROXY_LOG_DIR");
    CHECK(v.has_value() && *v == "NONE");
    CHECK(load_config().log_dir.empty());  // the sentinel is what actually reaches init_logging

    put_real_env("CPROXY_LOG_DIR", " none ");
    CHECK(load_config().log_dir.empty());  // trimmed and case-folded, like every other sentinel

    put_real_env("CPROXY_LOG_DIR", "/var/log/cproxy");
    CHECK(load_config().log_dir == "/var/log/cproxy");

    put_real_env("CPROXY_LOG_DIR", nullptr);
    CHECK(!system_env("CPROXY_LOG_DIR").has_value());
    CHECK(load_config().log_dir == "logs");
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

// The day-key gate has two arms: the write surface by method (any path), and CPROXY_DAYKEY_PATHS by
// path (any method, GET included). /news/default is gated by default so the protection does not
// depend on remembering an env var at deploy time.
void daykey_paths_gate_reads_by_default() {
    Config c = load_config(make_env({}));
    CHECK(c.daykey_paths.size() == 1);
    CHECK(c.daykey_paths[0] == "/news/default");

    // The gated read, at the real route prefix and bare.
    CHECK(c.daykey_required("GET", "/api/v1/news/default"));
    CHECK(c.daykey_required("HEAD", "/api/v1/news/default"));
    CHECK(c.daykey_required("GET", "/news/default"));
    // Trailing slash and casing must not be a way around it.
    CHECK(c.daykey_required("GET", "/api/v1/news/default/"));
    CHECK(c.daykey_required("GET", "/api/v1/News/Default"));
    // Anything nested under the gated path is gated too.
    CHECK(c.daykey_required("GET", "/api/v1/news/default/extra"));

    // Sibling news reads stay open — the gate is one endpoint, not the whole news surface.
    CHECK(!c.daykey_required("GET", "/api/v1/news/list"));
    CHECK(!c.daykey_required("GET", "/api/v1/news/search"));
    CHECK(!c.daykey_required("GET", "/api/v1/fish"));
    // The entry's leading '/' keeps the tail match on a segment boundary.
    CHECK(!c.daykey_required("GET", "/api/v1/oldnews/default"));

    // The write surface is still gated on every path, unchanged by any of the above.
    CHECK(c.daykey_required("POST", "/api/v1/river/regulation/x"));
    CHECK(c.daykey_required("PATCH", "/api/v1/river/fish/x"));
    CHECK(c.daykey_required("patch", "/api/v1/river/fish/x"));  // case-insensitive method
    // PUT/DELETE are deliberately NOT in the method arm: the allow-list is what blocks them.
    CHECK(!c.daykey_required("PUT", "/api/v1/river/fish/x"));
}

void daykey_paths_are_configurable_and_can_be_cleared() {
    Config c = load_config(make_env({{"CPROXY_DAYKEY_PATHS", "/news/default, fish/secret ,/x/y/"}}));
    CHECK(c.daykey_paths.size() == 3);
    CHECK(c.daykey_paths[1] == "/fish/secret");  // a missing leading '/' is supplied
    CHECK(c.daykey_paths[2] == "/x/y");          // a trailing '/' is stripped
    CHECK(c.daykey_required("GET", "/api/v1/fish/secret"));
    CHECK(c.daykey_required("GET", "/api/x/y"));

    // "NONE" is the off switch, and it must survive the casing an operator actually types.
    for (const char* off_value : {"NONE", "none", " None "}) {
        Config off = load_config(make_env({{"CPROXY_DAYKEY_PATHS", off_value}}));
        CHECK(off.daykey_paths.empty());
        CHECK(!off.daykey_required("GET", "/api/v1/news/default"));
        CHECK(off.daykey_required("POST", "/api/v1/news/default"));  // write surface is unaffected
    }

    // Why the off switch is a sentinel and not "": system_env() maps an empty variable to nullopt,
    // so in a real process CPROXY_DAYKEY_PATHS="" is indistinguishable from unset and MUST leave the
    // default gate standing. Asserted through system_env itself, because make_env would hand back a
    // real empty string and hide exactly the discrepancy this pins down (it did, once).
    CHECK(!system_env("CPROXY_DAYKEY_PATHS_DEFINITELY_UNSET_12345").has_value());
    Config empty = load_config([](const char* k) -> std::optional<std::string> {
        return std::string(k) == "CPROXY_DAYKEY_PATHS" ? system_env("PATH_THAT_IS_NOT_SET_98765")
                                                       : std::nullopt;
    });
    CHECK(empty.daykey_paths.size() == 1);
    CHECK(empty.daykey_required("GET", "/api/v1/news/default"));
}

}  // namespace

int main() {
    defaults_apply_when_env_is_empty();
    overrides_are_read_and_methods_restricted();
    malformed_int_falls_back_and_all_keyword_means_unrestricted();
    logging_env_is_read_including_console_only_sentinel();
    console_only_sentinel_works_through_the_real_environment();
    external_values_are_read_from_the_env_lookup();
    validation_accepts_defaults_and_rejects_nonsense();
    payload_limit_is_read_with_default();
    daykey_paths_gate_reads_by_default();
    daykey_paths_are_configurable_and_can_be_cleared();
    std::cout << "config_test: all assertions passed\n";
    return 0;
}
