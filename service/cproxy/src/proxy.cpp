#include "proxy.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <format>
#include <random>
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
 * X-Forwarded-* and X-Request-Id are excluded because this proxy IS the edge and sets its own
 * authoritative values — and httplib's set_header APPENDS to the multimap, so a copied inbound
 * (possibly spoofed) value would otherwise ride along next to ours.
 */
bool is_unforwardable(const std::string& key) {
    static const char* const drop[] = {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade", "host",
        "content-length", "content-type",
        "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-request-id"};
    for (const char* d : drop) {
        if (iequals(key, d)) return true;
    }
    return false;
}

/** Timing-safe equality for the API key: never short-circuits on the first differing byte. */
bool constant_time_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;  // only the length is observable
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

/** True when any path segment is exactly "..", i.e. the target tries to climb out of the prefix. */
bool has_dotdot_segment(const std::string& path) {
    std::size_t i = 0;
    while (i <= path.size()) {
        std::size_t j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        if (j - i == 2 && path[i] == '.' && path[i + 1] == '.') return true;
        i = j + 1;
    }
    return false;
}

bool valid_request_id(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '_';
    });
}

/** Caller-supplied X-Request-Id if well-formed, otherwise a freshly minted one. */
std::string request_id(const httplib::Request& req) {
    const std::string inbound = req.get_header_value("X-Request-Id");
    if (valid_request_id(inbound)) return inbound;
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    return std::format("{:016x}", rng());
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
    const std::string rid = request_id(req);
    res.set_header("X-Request-Id", rid);

    if (!cfg.method_allowed(req.method)) {
        write_error(res, 405, "method_not_allowed", "Method not allowed by this proxy");
        log_request(std::format("{} {} -> 405 (method not allowed)", req.method, req.path),
                    req.remote_addr, rid);
        return;
    }
    if (cfg.auth_required() &&
        !constant_time_equals(req.get_header_value("X-API-Key"), cfg.api_key)) {
        write_error(res, 401, "unauthorized", "Missing or invalid X-API-Key");
        log_request(std::format("{} {} -> 401 (bad api key)", req.method, req.path),
                    req.remote_addr, rid);
        return;
    }

    // Forward the RAW request target (exact bytes from the request line) so no decode/re-encode
    // round trip happens at the proxy; fall back to a rebuild if the server didn't capture it.
    std::string target = req.target.empty() ? forward_target(req) : req.target;
    // Dot-dot segments must die here: the upstream may normalize them and escape the route prefix
    // (e.g. /api/../actuator on a Spring upstream). req.path is the decoded form (catches %2e%2e);
    // the raw target's path portion catches the plain form.
    if (has_dotdot_segment(req.path) || has_dotdot_segment(target.substr(0, target.find('?')))) {
        write_error(res, 400, "bad_request", "Path traversal is not allowed");
        log_request(std::format("{} {} -> 400 (dot-dot path)", req.method, req.path),
                    req.remote_addr, rid);
        return;
    }

    httplib::Client cli(cfg.docapi_upstream);
    cli.set_connection_timeout(0, cfg.connect_timeout_ms * 1000);
    cli.set_read_timeout(cfg.read_timeout_ms / 1000, (cfg.read_timeout_ms % 1000) * 1000);
    cli.set_keep_alive(false);

    httplib::Request out;
    out.method = req.method;
    out.path = target;
    out.body = req.body;
    for (const auto& [k, v] : req.headers) {
        if (!is_unforwardable(k)) out.set_header(k.c_str(), v.c_str());
    }
    // Standard forwarding provenance headers + the correlation id.
    out.set_header("X-Forwarded-For", req.remote_addr);
    out.set_header("X-Forwarded-Host", req.get_header_value("Host"));
    out.set_header("X-Forwarded-Proto", "http");
    out.set_header("X-Request-Id", rid);

    auto started = std::chrono::steady_clock::now();
    auto result = cli.send(out);
    auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started)
                    .count();

    if (!result) {
        write_error(res, 502, "bad_gateway", "Upstream docapi is unreachable");
        log_request(std::format("{} {} -> 502 (upstream error {}, {}ms)", req.method, req.path,
                                httplib::to_string(result.error()), took),
                    req.remote_addr, rid);
        return;
    }

    res.status = result->status;
    std::string content_type = result->get_header_value("Content-Type");
    if (content_type.empty()) content_type = "application/octet-stream";
    for (const auto& [k, v] : result->headers) {
        if (!is_unforwardable(k)) res.set_header(k.c_str(), v.c_str());
    }
    res.set_content(result->body, content_type.c_str());
    log_request(std::format("{} {} -> {} ({}ms)", req.method, req.path, result->status, took),
                req.remote_addr, rid);
}

}  // namespace

/** Escapes regex metacharacters so a literal route prefix can head an httplib route pattern. */
std::string regex_escape(const std::string& s) {
    static const std::string special = R"(\.^$|()[]{}*+?)";
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (special.find(c) != std::string::npos) out += '\\';
        out += c;
    }
    return out;
}

void install_routes(httplib::Server& server, const Config& cfg) {
    // Oversized request bodies are cut off with 413 while being read, before any handler runs.
    server.set_payload_max_length(static_cast<size_t>(cfg.max_payload_bytes));

    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(
            std::format("{{\"status\":\"UP\",\"service\":\"cproxy\",\"version\":\"{}\"}}",
                        CPROXY_VERSION),
            "application/json");
    });

    // Real per-method routes, NOT a pre_routing_handler: httplib runs pre-routing BEFORE reading
    // the request body, so a pre-routing proxy would forward POST/PUT bodies empty and the payload
    // limit would never fire. Registered routes get the body read (and capped) first.
    const std::string pattern = regex_escape(cfg.route_prefix) + ".*";
    const auto forward = [&cfg](const httplib::Request& req, httplib::Response& res) {
        proxy_to_docapi(cfg, req, res);
    };
    server.Get(pattern, forward);  // also serves HEAD
    server.Post(pattern, forward);
    server.Put(pattern, forward);
    server.Delete(pattern, forward);
    server.Patch(pattern, forward);
    server.Options(pattern, forward);

    // Fires for every >=400 response; our own handlers already wrote a JSON body, so only the
    // server-generated fallbacks (no-route 404, oversized 413) arrive here empty. Logging them
    // makes scanner probing visible (/health stays unlogged - the HEALTHCHECK runs every 30s).
    server.set_error_handler([](const httplib::Request& req, httplib::Response& res) {
        if (!res.body.empty()) return;
        const char* code = res.status == 404   ? "not_found"
                           : res.status == 413 ? "payload_too_large"
                                               : "error";
        const char* message = res.status == 404   ? "No route"
                              : res.status == 413 ? "Request body too large"
                                                  : "Request failed";
        res.set_content(std::format("{{\"error\":{{\"code\":\"{}\",\"message\":\"{}\"}}}}", code,
                                    message),
                        "application/json");
        log_request(std::format("{} {} -> {}", req.method, req.path, res.status), req.remote_addr,
                    request_id(req));
    });
}

}  // namespace cproxy
