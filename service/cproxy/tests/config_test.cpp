// Minimal, framework-free unit tests for config parsing. Registered with CTest; run via
// `ctest --test-dir build` (also executed inside the Docker build).
#include "check.hpp"
#include <cstdlib>  // setenv/unsetenv (POSIX), _putenv_s (Windows) — see put_real_env
#include <iostream>
#include <map>
#include <string>
#include <vector>

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
    CHECK(!c.rabbitmq_events_enabled);
    // No real infrastructure address in tests — same reason as docapi_upstream above.
    CHECK(c.rabbitmq_management_url.empty());
    CHECK(c.rabbitmq_username == "fishfind");
    CHECK(c.rabbitmq_queue == "fishfind.account.events");
    CHECK(c.account_mirror_db_path == "/var/lib/cproxy/auth.sqlite");
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

// A broken RabbitMQ mirror must DEGRADE, never take the proxy down. Forwarding /api/* does not
// depend on the mirror in any way, so a missing management URL or password has to leave startup
// alone and disable only the consumer. Treating it as fatal is what took the public edge offline on
// the 0.9.2 deploy: validate_config flagged the empty URL, main() exited, and port 80 stopped
// binding — an outage caused by a feature that was doing nothing for request handling.
void rabbitmq_misconfig_degrades_the_mirror_not_the_proxy() {
    // Placeholder host — no real infrastructure address in tests. rabbitmq_management_url has no
    // default (see config.hpp), so it must be supplied explicitly whenever events are enabled, same
    // as the password.
    Config ok = load_config(make_env({{"CPROXY_RABBITMQ_EVENTS_ENABLED", "true"},
                                      {"CPROXY_RABBITMQ_MANAGEMENT_URL", "https://rabbitmq.example.invalid:15671"},
                                      {"CPROXY_RABBITMQ_PASSWORD", "secret"}}));
    CHECK(ok.rabbitmq_events_enabled);
    CHECK(ok.rabbitmq_password == "secret");
    CHECK(validate_config(ok).empty());
    CHECK(rabbitmq_config_problems(ok).empty());

    // Enabled with no URL and no password: startup must survive, and the problems must be reported
    // through the separate channel so main() can log them and switch the consumer off.
    Config unset_url = load_config(make_env({{"CPROXY_RABBITMQ_EVENTS_ENABLED", "true"}}));
    CHECK(unset_url.rabbitmq_management_url.empty());
    CHECK(validate_config(unset_url).empty());
    CHECK(rabbitmq_config_problems(unset_url).size() >= 2);  // URL and password

    // Same for a schemeless URL / zero poll interval.
    Config bad = load_config(make_env({{"CPROXY_RABBITMQ_EVENTS_ENABLED", "true"},
                                       {"CPROXY_RABBITMQ_MANAGEMENT_URL", "rabbit:15671"},
                                       {"CPROXY_RABBITMQ_PASSWORD", ""},
                                       {"CPROXY_RABBITMQ_POLL_MS", "0"}}));
    CHECK(validate_config(bad).empty());
    CHECK(rabbitmq_config_problems(bad).size() >= 2);

    // Disabled entirely: nothing to report, whatever the other values are.
    Config off = load_config(make_env({}));
    CHECK(!off.rabbitmq_events_enabled);
    CHECK(rabbitmq_config_problems(off).empty());
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
    CHECK(c.daykey_paths.size() == 4);
    CHECK(c.daykey_paths[0] == "/news/default");
    CHECK(c.daykey_paths[1] == "/news/featured");
    CHECK(c.daykey_paths[2] == "/news/more");
    CHECK(c.daykey_paths[3] == "/news/photo");

    // The gated read, at the real route prefix and bare.
    CHECK(c.daykey_required("GET", "/api/v1/news/default"));
    CHECK(c.daykey_required("HEAD", "/api/v1/news/default"));
    CHECK(c.daykey_required("GET", "/news/default"));
    // Trailing slash and casing must not be a way around it.
    CHECK(c.daykey_required("GET", "/api/v1/news/default/"));
    CHECK(c.daykey_required("GET", "/api/v1/News/Default"));
    // Anything nested under the gated path is gated too.
    CHECK(c.daykey_required("GET", "/api/v1/news/default/extra"));

    // THE BYPASS: docapi 1.8.1 split /news/default into these two, which serve the same content.
    // Gating only /news/default would leave the expensive half (~1.09 MB of lead articles) readable
    // with no credential — which is exactly what shipped, briefly, before this default was widened.
    CHECK(c.daykey_required("GET", "/api/v1/news/featured"));
    CHECK(c.daykey_required("GET", "/api/v1/news/more"));
    CHECK(c.daykey_required("HEAD", "/api/v1/news/featured"));
    CHECK(c.daykey_required("GET", "/api/v1/news/featured/"));
    CHECK(c.daykey_required("GET", "/api/v1/News/Featured"));
    CHECK(c.daykey_required("GET", "/api/v1/news/more/"));
    CHECK(c.daykey_required("GET", "/api/v1/News/More"));

    // docapi 1.9.0 added /news/photo/<id>: the SAME lead photos /news/featured embeds as base64,
    // served by id as raw bytes. Leaving it open would be the bypass a third time, so it is gated
    // with the rest of the home page. Note the credential is checked on the id-bearing form -- the
    // bare /news/photo is a 404 upstream and is not what a scraper would call.
    CHECK(c.daykey_required("GET", "/api/v1/news/photo/1B4E28BA-2FA1-11D2-883F-0016D3CCA427"));
    CHECK(c.daykey_required("HEAD", "/api/v1/news/photo/1B4E28BA-2FA1-11D2-883F-0016D3CCA427"));
    CHECK(c.daykey_required("GET", "/api/v1/News/Photo/1B4E28BA-2FA1-11D2-883F-0016D3CCA427"));
    CHECK(c.daykey_required("GET", "/api/v1/news/photo"));
    CHECK(c.daykey_required("GET", "/api/v1/news/photo/"));

    // Sibling news reads stay open — the gate is the home page, not the whole news surface.
    CHECK(!c.daykey_required("GET", "/api/v1/news/list"));
    CHECK(!c.daykey_required("GET", "/api/v1/news/search"));
    CHECK(!c.daykey_required("GET", "/api/v1/fish"));
    // A near-miss must not be swept in by the new entries either.
    CHECK(!c.daykey_required("GET", "/api/v1/news/moreish"));
    CHECK(!c.daykey_required("GET", "/api/v1/oldnews/more"));
    CHECK(!c.daykey_required("GET", "/api/v1/news/photograph"));
    CHECK(!c.daykey_required("GET", "/api/v1/oldnews/photo/x"));
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
    CHECK(empty.daykey_paths.size() == 4);
    CHECK(empty.daykey_required("GET", "/api/v1/news/default"));
    CHECK(empty.daykey_required("GET", "/api/v1/news/featured"));
    CHECK(empty.daykey_required("GET", "/api/v1/news/more"));
    CHECK(empty.daykey_required("GET", "/api/v1/news/photo/x"));
}

void jwt_is_off_until_a_secret_is_configured() {
    Config c = load_config(make_env({}));
    CHECK(!c.jwt_enabled());
    CHECK(!c.jwt_require_user);
    // Defaults match what the frontend mints (doc/envfish-jwt.html); a mismatch here rejects every
    // real token, so pin them.
    CHECK(c.jwt_issuer == "envfish");
    CHECK(c.jwt_audience == "fishfind.info");
    CHECK(c.jwt_subject == "cproxy");
    CHECK(c.jwt_leeway_seconds == 300);
    CHECK(c.jwt_user_cache_seconds == 60);
    CHECK(validate_config(c).empty());
}

void jwt_settings_are_read_and_claim_checks_can_be_switched_off() {
    Config c = load_config(make_env({{"CPROXY_JWT_SECRET", "s3cr3t"},
                                     {"CPROXY_JWT_REQUIRE_USER", "yes"},
                                     {"CPROXY_JWT_LEEWAY_SECONDS", "30"},
                                     {"CPROXY_JWT_USER_CACHE_SECONDS", "5"},
                                     {"CPROXY_JWT_ISSUER", "elsewhere"},
                                     {"CPROXY_JWT_AUDIENCE", "NONE"},
                                     {"CPROXY_JWT_SUBJECT", " none "}}));
    CHECK(c.jwt_enabled());
    CHECK(c.jwt_require_user);
    CHECK(c.jwt_leeway_seconds == 30);
    CHECK(c.jwt_user_cache_seconds == 5);
    CHECK(c.jwt_issuer == "elsewhere");
    CHECK(c.jwt_audience.empty());  // "NONE" = do not check this claim
    CHECK(c.jwt_subject.empty());   // and it survives the casing an operator actually types
    CHECK(validate_config(c).empty());
}

void a_jwt_switch_without_a_secret_is_a_startup_error() {
    // Account checks on tokens, with no secret to verify tokens with, cannot mean what the operator
    // intended, so it is fatal.
    CHECK(!validate_config(load_config(make_env({{"CPROXY_JWT_REQUIRE_USER", "true"}}))).empty());

    // The user check additionally needs the mirror it reads.
    Config no_mirror = load_config(make_env({{"CPROXY_JWT_SECRET", "s"},
                                             {"CPROXY_JWT_REQUIRE_USER", "true"}}));
    no_mirror.account_mirror_db_path.clear();
    CHECK(!validate_config(no_mirror).empty());

    CHECK(validate_config(load_config(make_env({{"CPROXY_JWT_SECRET", "s"}}))).empty());
    CHECK(!validate_config(load_config(make_env({{"CPROXY_JWT_SECRET", "s"},
                                                 {"CPROXY_JWT_USER_CACHE_SECONDS", "0"}})))
               .empty());
}

// 0.13.0 removed CPROXY_JWT_REQUIRED along with the X-Day-Guid header it governed. A compose file
// that still sets it -- to either value -- must neither fail startup nor change anything, and a
// missing secret on its own is not fatal (it shuts only the gated surface; see check_gate_credential).
void the_retired_jwt_required_switch_is_ignored() {
    for (const char* value : {"true", "false"}) {
        const Config with = load_config(make_env({{"CPROXY_JWT_SECRET", "s"},
                                                  {"CPROXY_JWT_REQUIRED", value}}));
        const Config without = load_config(make_env({{"CPROXY_JWT_SECRET", "s"}}));
        CHECK(validate_config(with).empty());
        CHECK(with.jwt_enabled() == without.jwt_enabled());
        CHECK(with.jwt_require_user == without.jwt_require_user);
    }
    CHECK(validate_config(load_config(make_env({{"CPROXY_JWT_REQUIRED", "false"}}))).empty());
    CHECK(validate_config(load_config(make_env({}))).empty());
}

// --- Clock alignment knobs (0.11.0) -------------------------------------------------------------

void clock_sync_defaults_are_the_documented_ones() {
    const Config cfg = load_config(make_env({}));
    // On by default, but inert until the account mirror holds a live access = 255 account whose
    // token arrives with an X-Client-Time header (0.12.0: admin is looked up, never claimed).
    CHECK(cfg.jwt_clock_sync);
    CHECK(cfg.jwt_clock_sync_threshold_seconds == 5);
    CHECK(cfg.jwt_clock_sync_max_seconds == 3600);
}

void clock_sync_reads_its_env_vars() {
    const Config cfg = load_config(make_env({{"CPROXY_JWT_CLOCK_SYNC", "false"},
                                             {"CPROXY_JWT_CLOCK_SYNC_THRESHOLD_SECONDS", "30"},
                                             {"CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS", "900"}}));
    CHECK(!cfg.jwt_clock_sync);
    CHECK(cfg.jwt_clock_sync_threshold_seconds == 30);
    CHECK(cfg.jwt_clock_sync_max_seconds == 900);
}

/**
 * Through the REAL environment, per the rule this file already pins for CPROXY_LOG_DIR: the fake
 * hands back a genuine empty string that a process environment never produces, so a switch asserted
 * only through make_env can be a silent no-op in production while its unit test passes.
 *
 * The consequence to know here is that `-e CPROXY_JWT_CLOCK_SYNC=` does NOT turn the feature off --
 * it reads as unset and leaves the default `true` standing. The off value is the word `false`.
 */
void an_empty_clock_sync_variable_reads_as_unset_not_as_off() {
    put_real_env("CPROXY_JWT_CLOCK_SYNC", "");
    CHECK(load_config(system_env).jwt_clock_sync);  // default survived -- NOT turned off

    put_real_env("CPROXY_JWT_CLOCK_SYNC", "false");
    CHECK(!load_config(system_env).jwt_clock_sync);

    put_real_env("CPROXY_JWT_CLOCK_SYNC", nullptr);
    CHECK(load_config(system_env).jwt_clock_sync);
}

void a_ceiling_below_the_threshold_is_refused() {
    // Otherwise the feature looks enabled and can never correct anything: the trigger point sits
    // above the largest correction the ceiling permits.
    Config cfg = load_config(make_env({{"CPROXY_JWT_CLOCK_SYNC_THRESHOLD_SECONDS", "600"},
                                       {"CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS", "60"}}));
    const std::vector<std::string> errors = validate_config(cfg);
    CHECK(!errors.empty());

    // ...but the same pair is fine once the feature is off, because nothing will read either value.
    cfg.jwt_clock_sync = false;
    CHECK(validate_config(cfg).empty());
}

void a_zero_ceiling_is_legal_and_pins_the_host_clock() {
    // 0 is the "never move, but leave the plumbing in place" setting. It is only coherent with the
    // feature off, which the cross-check above enforces -- so assert exactly that combination.
    Config cfg = load_config(make_env({{"CPROXY_JWT_CLOCK_SYNC", "false"},
                                       {"CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS", "0"}}));
    CHECK(cfg.jwt_clock_sync_max_seconds == 0);
    CHECK(validate_config(cfg).empty());
}

}  // namespace

int main() {
    defaults_apply_when_env_is_empty();
    overrides_are_read_and_methods_restricted();
    malformed_int_falls_back_and_all_keyword_means_unrestricted();
    logging_env_is_read_including_console_only_sentinel();
    console_only_sentinel_works_through_the_real_environment();
    external_values_are_read_from_the_env_lookup();
    rabbitmq_misconfig_degrades_the_mirror_not_the_proxy();
    validation_accepts_defaults_and_rejects_nonsense();
    payload_limit_is_read_with_default();
    daykey_paths_gate_reads_by_default();
    daykey_paths_are_configurable_and_can_be_cleared();
    jwt_is_off_until_a_secret_is_configured();
    jwt_settings_are_read_and_claim_checks_can_be_switched_off();
    a_jwt_switch_without_a_secret_is_a_startup_error();
    the_retired_jwt_required_switch_is_ignored();
    clock_sync_defaults_are_the_documented_ones();
    clock_sync_reads_its_env_vars();
    an_empty_clock_sync_variable_reads_as_unset_not_as_off();
    a_ceiling_below_the_threshold_is_refused();
    a_zero_ceiling_is_legal_and_pins_the_host_clock();
    std::cout << "config_test: all assertions passed\n";
    return 0;
}

