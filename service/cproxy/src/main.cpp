#include <csignal>
#include <cstdlib>
#include <format>
#include <iostream>
#include <map>
#include <string>

#include <httplib.h>

#include "cloud_range_refresh.hpp"
#include "cloud_range_store.hpp"
#include "config.hpp"
#include "dotenv.hpp"
#include "log.hpp"
#include "proxy.hpp"
#include "rabbit_event_consumer.hpp"
#include "version.hpp"

namespace {

httplib::Server* g_server = nullptr;

void on_signal(int /*sig*/) {
    // stop() unblocks listen() so the process exits cleanly on SIGTERM/SIGINT (docker stop).
    if (g_server != nullptr) g_server->stop();
}

const char* set_or_unset(const std::string& v) { return v.empty() ? "unset" : "set"; }

}  // namespace

int main() {
    // The dotenv path decides where the rest of the config (incl. encrypted secrets) is read from, so
    // it is resolved directly from the environment first. A decryption failure here is fatal — a
    // missing/wrong master key must never be swallowed.
    const char* dotenv_path = std::getenv("CPROXY_DOTENV_PATH");
    std::map<std::string, std::string> dotenv;
    try {
        dotenv = cproxy::load_dotenv(dotenv_path != nullptr ? dotenv_path : "");
    } catch (const std::exception& ex) {
        std::cerr << std::format("{{\"service\":\"cproxy\",\"level\":\"FATAL\","
                                 "\"msg\":\"failed to load dotenv: {}\"}}",
                                 ex.what())
                  << std::endl;
        return 1;
    }

    const cproxy::EnvLookup env = cproxy::make_env_lookup(dotenv);
    cproxy::Config cfg = cproxy::load_config(env);

    // Fail fast on nonsense config (port 0, negative timeout, prefix without '/') instead of
    // limping into listen() with values that can only misbehave.
    if (const auto errors = cproxy::validate_config(cfg); !errors.empty()) {
        for (const auto& e : errors) {
            std::cerr << std::format("{{\"service\":\"cproxy\",\"level\":\"FATAL\","
                                     "\"msg\":\"invalid config: {}\"}}",
                                     e)
                      << std::endl;
        }
        return 1;
    }

    cproxy::init_logging(cfg.log_dir, cfg.log_max_history);

    // A misconfigured mirror must never cost us the proxy. These problems are reported and the
    // consumer is switched off; /api/* keeps serving. (Before 0.9.4 they were fatal, and an empty
    // management URL with events enabled took the public edge down on the 0.9.2 deploy.)
    if (const auto rabbit_problems = cproxy::rabbitmq_config_problems(cfg); !rabbit_problems.empty()) {
        for (const auto& p : rabbit_problems) {
            cproxy::log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"ERROR\","
                                        "\"msg\":\"RabbitMQ mirror disabled: {}\"}}",
                                        p));
        }
        cfg.rabbitmq_events_enabled = false;
    }

    httplib::Server server;
    g_server = &server;
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    // One range set shared by the request path and the refresh thread: the refresher swaps it
    // atomically, so new ranges take effect without a restart and no reader ever blocks.
    // Declared before install_routes so it outlives the handlers that capture a pointer to it.
    cproxy::CloudRangeStore cloud_ranges;
    cproxy::install_routes(server, cfg, &cloud_ranges);

    cproxy::CloudRangeRefresher refresher(cfg, cloud_ranges);
    refresher.start();

    cproxy::RabbitEventConsumer rabbit_events(cfg);
    rabbit_events.start();

    // external_admin / external_frontend are secret (encrypted at rest) — log only their presence.
    cproxy::log_raw(std::format(
        "{{\"service\":\"cproxy\",\"version\":\"{}\",\"msg\":\"starting\","
        "\"listen\":\"{}:{}\",\"route_prefix\":\"{}\",\"docapi_upstream\":\"{}\","
        "\"auth\":{},\"methods\":\"{}\",\"log_dir\":\"{}\",\"dotenv\":\"{}\","
        "\"breaker\":\"{}\",\"retry\":{},\"daykey_db\":\"{}\","
        "\"jwt\":\"{}\",\"jwt_leeway_s\":{},\"clock_sync\":\"{}\","
        "\"external_admin\":\"{}\",\"external_frontend\":\"{}\"}}",
        CPROXY_VERSION, cfg.listen_addr, cfg.listen_port, cfg.route_prefix, cfg.docapi_upstream,
        cfg.auth_required() ? "true" : "false",
        cfg.allowed_methods.empty() ? "ALL" : "restricted",
        cfg.log_dir.empty() ? "(stdout only)" : cfg.log_dir,
        (dotenv_path != nullptr && *dotenv_path != '\0') ? dotenv_path : "(none)",
        cfg.breaker_threshold > 0
            ? std::format("{} fails / {}ms", cfg.breaker_threshold, cfg.breaker_cooldown_ms)
            : std::string("disabled"),
        cfg.upstream_retry,
        cfg.daykey_db_path.empty() ? "(unconfigured, gated requests always 500)" : cfg.daykey_db_path,
        // The secret itself is never logged, only whether the gate can open and how strictly — the
        // one thing an operator needs from this line after a change.
        !cfg.jwt_enabled() ? std::string("off (CPROXY_JWT_SECRET unset, gated requests always 500)")
                           : std::format("on (bearer only, user claim {})",
                                         cfg.jwt_require_user ? "enforced" : "ignored"),
        cfg.jwt_leeway_seconds,
        // The offset always starts at zero; this line reports the POLICY, so an operator reading a
        // "clock aligned from admin token" WARN later can tell whether it was expected.
        cfg.jwt_clock_sync ? std::format("on (>{}s, max {}s)", cfg.jwt_clock_sync_threshold_seconds,
                                         cfg.jwt_clock_sync_max_seconds)
                           : std::string("off (host clock only)"),
        set_or_unset(cfg.external_admin), set_or_unset(cfg.external_frontend)));

    // Without a secret no token can be verified, and since 0.13.0 there is no other credential, so
    // the whole gated surface (every write, the news home-page reads) is shut. Not fatal -- the
    // ungated reads keep serving -- but loud, because otherwise it only shows as a wall of 500s.
    if (!cfg.jwt_enabled()) {
        cproxy::log_raw(
            "{\"service\":\"cproxy\",\"level\":\"ERROR\",\"msg\":\"CPROXY_JWT_SECRET is unset: "
            "every gated request (POST, PATCH, CPROXY_DAYKEY_PATHS) will answer 500\"}");
    }
    // The switch that used to decide whether the bare X-Day-Guid header was still honoured is gone.
    // Say so if a leftover compose file still sets it, so nobody mistakes "false" for a rollback.
    if (env("CPROXY_JWT_REQUIRED").has_value()) {
        cproxy::log_raw(
            "{\"service\":\"cproxy\",\"level\":\"WARN\",\"msg\":\"CPROXY_JWT_REQUIRED is set but "
            "ignored: X-Day-Guid was removed in 0.13.0 and a bearer JWT is the only credential\"}");
    }

    if (!server.listen(cfg.listen_addr, cfg.listen_port)) {
        rabbit_events.stop();
        cproxy::log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"FATAL\","
                                    "\"msg\":\"failed to bind {}:{}\"}}",
                                    cfg.listen_addr, cfg.listen_port));
        return 1;
    }
    rabbit_events.stop();
    return 0;
}

