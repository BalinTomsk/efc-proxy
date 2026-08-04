#include "proxy.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>

#include "breaker.hpp"
#include "log.hpp"
#include "version.hpp"

namespace cproxy {

namespace {

/** Process-wide counters behind one mutex; contention is nil next to the network I/O. */
struct Metrics {
    mutable std::mutex mu;
    std::map<int, long long> responses_by_status;
    long long upstream_latency_ms_sum = 0;
    long long upstream_exchanges = 0;   // completed upstream calls (any HTTP status)
    long long upstream_failures = 0;    // transport failures (unreachable/timeout)
    long long short_circuited = 0;      // requests refused without touching the upstream
    long long retries = 0;

    void observe_response(int status) {
        std::lock_guard<std::mutex> lock(mu);
        ++responses_by_status[status];
    }
    void observe_exchange(long long ms) {
        std::lock_guard<std::mutex> lock(mu);
        upstream_latency_ms_sum += ms;
        ++upstream_exchanges;
    }
    void observe_failure() {
        std::lock_guard<std::mutex> lock(mu);
        ++upstream_failures;
    }
    void observe_short_circuit() {
        std::lock_guard<std::mutex> lock(mu);
        ++short_circuited;
    }
    void observe_retry() {
        std::lock_guard<std::mutex> lock(mu);
        ++retries;
    }
};

/**
 * Per-server runtime state. Deliberately NOT global: the tests stand several proxies up in one
 * process, and a shared breaker/counter set would leak between them. install_routes() owns one of
 * these via shared_ptr and every handler captures it, so its lifetime matches the handlers'.
 */
struct ProxyState {
    CircuitBreaker breaker;
    Metrics metrics;

    explicit ProxyState(const Config& cfg)
        : breaker(cfg.breaker_threshold, std::chrono::milliseconds(cfg.breaker_cooldown_ms)) {}
};

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

/**
 * The upstream client for THIS worker thread, kept alive between requests.
 *
 * A fresh Client per request meant a TCP connect + teardown on every call. httplib's Client keeps
 * the socket open and checks it is still alive before reuse, so the steady state is one connection
 * per worker thread. It is thread_local rather than shared because a single Client serializes
 * concurrent requests on its own mutex, which would defeat the point.
 */
httplib::Client& pooled_client(const Config& cfg) {
    thread_local std::string bound_upstream;
    thread_local std::unique_ptr<httplib::Client> client;
    if (!client || bound_upstream != cfg.docapi_upstream) {
        client = std::make_unique<httplib::Client>(cfg.docapi_upstream);
        client->set_keep_alive(true);
        bound_upstream = cfg.docapi_upstream;
    }
    // Re-applied per request so a config change is picked up without rebuilding the connection.
    client->set_connection_timeout(0, cfg.connect_timeout_ms * 1000);
    client->set_read_timeout(cfg.read_timeout_ms / 1000, (cfg.read_timeout_ms % 1000) * 1000);
    return *client;
}

/**
 * Safe to send twice when the first attempt never produced a response. Restricted to the methods
 * that are idempotent by definition — a retried POST could double-submit.
 */
bool is_retryable_method(const std::string& method) {
    return method == "GET" || method == "HEAD" || method == "OPTIONS";
}

/** Forwards one request to the docapi upstream and copies the response back. */
void proxy_to_docapi(const Config& cfg, ProxyState& state, const httplib::Request& req,
                     httplib::Response& res) {
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

    // Fail fast while the breaker is open: an outage would otherwise make every request pay the
    // full connect timeout and hold a worker thread for it.
    if (!state.breaker.allow(std::chrono::steady_clock::now())) {
        state.metrics.observe_short_circuit();
        write_error(res, 502, "upstream_unavailable",
                    "Upstream is unavailable (circuit breaker open)");
        log_request(std::format("{} {} -> 502 (circuit open)", req.method, req.path),
                    req.remote_addr, rid);
        return;
    }

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

    httplib::Client& cli = pooled_client(cfg);
    auto started = std::chrono::steady_clock::now();
    auto result = cli.send(out);
    // A pooled connection the upstream closed while idle fails on first use through no fault of
    // this request; one retry (idempotent methods only) turns that into a normal response instead
    // of a spurious 502. httplib drops the dead socket on failure, so the retry reconnects.
    if (!result && cfg.upstream_retry > 0 && is_retryable_method(req.method)) {
        state.metrics.observe_retry();
        result = cli.send(out);
    }
    auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started)
                    .count();

    if (!result) {
        state.breaker.on_failure(std::chrono::steady_clock::now());
        state.metrics.observe_failure();
        write_error(res, 502, "bad_gateway", "Upstream docapi is unreachable");
        log_request(std::format("{} {} -> 502 (upstream error {}, {}ms)", req.method, req.path,
                                httplib::to_string(result.error()), took),
                    req.remote_addr, rid);
        return;
    }
    // Reachable upstream: an HTTP error status is the upstream's answer, not a transport failure,
    // so it closes the breaker like any other response.
    state.breaker.on_success();
    state.metrics.observe_exchange(took);

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

/** Prometheus text exposition of the current counters. */
std::string render_metrics(const ProxyState& state) {
    std::string out;
    {
        std::lock_guard<std::mutex> lock(state.metrics.mu);
        out += "# HELP cproxy_requests_total Responses served, by HTTP status.\n";
        out += "# TYPE cproxy_requests_total counter\n";
        for (const auto& [status, count] : state.metrics.responses_by_status) {
            out += std::format("cproxy_requests_total{{status=\"{}\"}} {}\n", status, count);
        }
        out += "# HELP cproxy_upstream_latency_ms Time spent in completed upstream calls.\n";
        out += "# TYPE cproxy_upstream_latency_ms summary\n";
        out += std::format("cproxy_upstream_latency_ms_sum {}\n", state.metrics.upstream_latency_ms_sum);
        out += std::format("cproxy_upstream_latency_ms_count {}\n", state.metrics.upstream_exchanges);
        out += "# HELP cproxy_upstream_failures_total Transport failures reaching the upstream.\n";
        out += "# TYPE cproxy_upstream_failures_total counter\n";
        out += std::format("cproxy_upstream_failures_total {}\n", state.metrics.upstream_failures);
        out += "# HELP cproxy_upstream_retries_total Idempotent requests retried once.\n";
        out += "# TYPE cproxy_upstream_retries_total counter\n";
        out += std::format("cproxy_upstream_retries_total {}\n", state.metrics.retries);
        out += "# HELP cproxy_short_circuited_total Requests refused with the breaker open.\n";
        out += "# TYPE cproxy_short_circuited_total counter\n";
        out += std::format("cproxy_short_circuited_total {}\n", state.metrics.short_circuited);
    }
    out += "# HELP cproxy_breaker_state Upstream circuit breaker: 0 closed, 1 open, 2 half-open.\n";
    out += "# TYPE cproxy_breaker_state gauge\n";
    out += std::format("cproxy_breaker_state {}\n",
                       static_cast<int>(state.breaker.state(std::chrono::steady_clock::now())));
    return out;
}

}  // namespace

void install_routes(httplib::Server& server, const Config& cfg) {
    // Per-server state (breaker + counters), captured by value into every handler so it lives
    // exactly as long as they do. See ProxyState for why this is not a global.
    auto state = std::make_shared<ProxyState>(cfg);

    // Oversized request bodies are cut off with 413 while being read, before any handler runs.
    server.set_payload_max_length(static_cast<size_t>(cfg.max_payload_bytes));

    // Liveness: is the proxy process itself serving? Never depends on the upstream, so an upstream
    // outage does not make an orchestrator kill an otherwise-healthy proxy.
    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(
            std::format("{{\"status\":\"UP\",\"service\":\"cproxy\",\"version\":\"{}\"}}",
                        CPROXY_VERSION),
            "application/json");
    });

    // Readiness: can this proxy currently serve useful traffic? Reports the breaker's view of the
    // upstream (503 while open) rather than probing on demand, which would hammer a sick upstream.
    server.Get("/health/ready", [state](const httplib::Request&, httplib::Response& res) {
        const auto s = state->breaker.state(std::chrono::steady_clock::now());
        const bool ready = s != CircuitBreaker::State::Open;
        res.status = ready ? 200 : 503;
        res.set_content(
            std::format("{{\"status\":\"{}\",\"service\":\"cproxy\",\"upstream\":\"{}\"}}",
                        ready ? "UP" : "DOWN", to_string(s)),
            "application/json");
    });

    server.Get("/metrics", [state](const httplib::Request&, httplib::Response& res) {
        res.set_content(render_metrics(*state), "text/plain; version=0.0.4");
    });

    // Real per-method routes, NOT a pre_routing_handler: httplib runs pre-routing BEFORE reading
    // the request body, so a pre-routing proxy would forward POST/PUT bodies empty and the payload
    // limit would never fire. Registered routes get the body read (and capped) first.
    const std::string pattern = regex_escape(cfg.route_prefix) + ".*";
    const auto forward = [&cfg, state](const httplib::Request& req, httplib::Response& res) {
        proxy_to_docapi(cfg, *state, req, res);
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

    // Runs for EVERY response (after the error handler, before the bytes go out), so it is the one
    // place that sees every status exactly once - proxied, local, and server-generated alike.
    server.set_post_routing_handler(
        [state](const httplib::Request&, const httplib::Response& res) {
            state->metrics.observe_response(res.status);
        });
}

}  // namespace cproxy
