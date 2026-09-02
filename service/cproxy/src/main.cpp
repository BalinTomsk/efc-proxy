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

    const cproxy::Config cfg = cproxy::load_config(cproxy::make_env_lookup(dotenv));

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

    // external_admin / external_frontend are secret (encrypted at rest) — log only their presence.
    cproxy::log_raw(std::format(
        "{{\"service\":\"cproxy\",\"version\":\"{}\",\"msg\":\"starting\","
        "\"listen\":\"{}:{}\",\"route_prefix\":\"{}\",\"docapi_upstream\":\"{}\","
        "\"auth\":{},\"methods\":\"{}\",\"log_dir\":\"{}\",\"dotenv\":\"{}\","
        "\"breaker\":\"{}\",\"retry\":{},\"daykey_db\":\"{}\","
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
        cfg.daykey_db_path.empty() ? "(unconfigured, PATCH always 500s)" : cfg.daykey_db_path,
        set_or_unset(cfg.external_admin), set_or_unset(cfg.external_frontend)));

    if (!server.listen(cfg.listen_addr, cfg.listen_port)) {
        cproxy::log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"FATAL\","
                                    "\"msg\":\"failed to bind {}:{}\"}}",
                                    cfg.listen_addr, cfg.listen_port));
        return 1;
    }
    return 0;
}
