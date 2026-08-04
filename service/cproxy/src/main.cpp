#include <csignal>
#include <format>

#include <httplib.h>

#include "config.hpp"
#include "log.hpp"
#include "proxy.hpp"
#include "version.hpp"

namespace {

httplib::Server* g_server = nullptr;

void on_signal(int /*sig*/) {
    // stop() unblocks listen() so the process exits cleanly on SIGTERM/SIGINT (docker stop).
    if (g_server != nullptr) g_server->stop();
}

}  // namespace

int main() {
    const cproxy::Config cfg = cproxy::load_config();
    cproxy::init_logging(cfg.log_dir, cfg.log_max_history);

    httplib::Server server;
    g_server = &server;
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    cproxy::install_routes(server, cfg);

    cproxy::log_raw(std::format(
        "{{\"service\":\"cproxy\",\"version\":\"{}\",\"msg\":\"starting\","
        "\"listen\":\"{}:{}\",\"route_prefix\":\"{}\",\"docapi_upstream\":\"{}\","
        "\"auth\":{},\"methods\":\"{}\",\"log_dir\":\"{}\"}}",
        CPROXY_VERSION, cfg.listen_addr, cfg.listen_port, cfg.route_prefix, cfg.docapi_upstream,
        cfg.auth_required() ? "true" : "false",
        cfg.allowed_methods.empty() ? "ALL" : "restricted",
        cfg.log_dir.empty() ? "(stdout only)" : cfg.log_dir));

    if (!server.listen(cfg.listen_addr, cfg.listen_port)) {
        cproxy::log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"FATAL\","
                                    "\"msg\":\"failed to bind {}:{}\"}}",
                                    cfg.listen_addr, cfg.listen_port));
        return 1;
    }
    return 0;
}
