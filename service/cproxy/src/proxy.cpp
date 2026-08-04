#include "proxy.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <format>
#include <string>

#include "log.hpp"
#include "version.hpp"

namespace cproxy {

namespace {

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
        return std::tolower(x) == std::tolower(y);
    });
}

/**
 * Hop-by-hop headers (RFC 7230 §6.1) must not be forwarded by a proxy. Host/Content-Length/
 * Content-Type are also excluded because the httplib client/response sets them itself.
 */
bool is_unforwardable(const std::string& key) {
    static const char* const drop[] = {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade", "host",
        "content-length", "content-type"};
    for (const char* d : drop) {
        if (iequals(key, d)) return true;
    }
    return false;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

/** Reconstructs the request-target (path plus query string) to forward verbatim. */
std::string forward_target(const httplib::Request& req) {
    std::string target = req.path;
    if (!req.params.empty()) {
        target += "?" + httplib::detail::params_to_query_str(req.params);
    }
    return target;
}

void write_error(httplib::Response& res, int status, const std::string& code,
                 const std::string& message) {
    res.status = status;
    res.set_content(std::format("{{\"error\":{{\"code\":\"{}\",\"message\":\"{}\"}}}}", code, message),
                    "application/json");
}

/** Forwards one request to the docapi upstream and copies the response back. */
void proxy_to_docapi(const Config& cfg, const httplib::Request& req, httplib::Response& res) {
    if (!cfg.method_allowed(req.method)) {
        write_error(res, 405, "method_not_allowed", "Method not allowed by this proxy");
        log_line(std::format("{} {} -> 405 (method not allowed)", req.method, req.path));
        return;
    }
    if (cfg.auth_required() && req.get_header_value("X-API-Key") != cfg.api_key) {
        write_error(res, 401, "unauthorized", "Missing or invalid X-API-Key");
        log_line(std::format("{} {} -> 401 (bad api key)", req.method, req.path));
        return;
    }

    httplib::Client cli(cfg.docapi_upstream);
    cli.set_connection_timeout(0, cfg.connect_timeout_ms * 1000);
    cli.set_read_timeout(cfg.read_timeout_ms / 1000, (cfg.read_timeout_ms % 1000) * 1000);
    cli.set_keep_alive(false);

    httplib::Request out;
    out.method = req.method;
    out.path = forward_target(req);
    out.body = req.body;
    for (const auto& [k, v] : req.headers) {
        if (!is_unforwardable(k)) out.set_header(k.c_str(), v.c_str());
    }
    // Standard forwarding provenance headers.
    out.set_header("X-Forwarded-For", req.remote_addr);
    out.set_header("X-Forwarded-Host", req.get_header_value("Host"));
    out.set_header("X-Forwarded-Proto", "http");

    auto started = std::chrono::steady_clock::now();
    auto result = cli.send(out);
    auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started)
                    .count();

    if (!result) {
        write_error(res, 502, "bad_gateway", "Upstream docapi is unreachable");
        log_line(std::format("{} {} -> 502 (upstream error {}, {}ms)", req.method, req.path,
                             httplib::to_string(result.error()), took));
        return;
    }

    res.status = result->status;
    std::string content_type = result->get_header_value("Content-Type");
    if (content_type.empty()) content_type = "application/octet-stream";
    for (const auto& [k, v] : result->headers) {
        if (!is_unforwardable(k)) res.set_header(k.c_str(), v.c_str());
    }
    res.set_content(result->body, content_type.c_str());
    log_line(std::format("{} {} -> {} ({}ms)", req.method, req.path, result->status, took));
}

}  // namespace

void install_routes(httplib::Server& server, const Config& cfg) {
    // pre_routing_handler is invoked for every method/path, so it is the single place to
    // catch-all: handle /health and the proxied prefix, and let anything else 404.
    server.set_pre_routing_handler(
        [&cfg](const httplib::Request& req, httplib::Response& res) {
            if (req.path == "/health") {
                res.set_content(
                    std::format("{{\"status\":\"UP\",\"service\":\"cproxy\",\"version\":\"{}\"}}",
                                CPROXY_VERSION),
                    "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            if (starts_with(req.path, cfg.route_prefix)) {
                proxy_to_docapi(cfg, req, res);
                return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });

    // Fallback for any path not handled above.
    server.set_error_handler([](const httplib::Request&, httplib::Response& res) {
        if (res.body.empty()) {
            res.set_content(
                std::format("{{\"error\":{{\"code\":\"not_found\",\"message\":\"No route\"}}}}"),
                "application/json");
        }
    });
}

}  // namespace cproxy
