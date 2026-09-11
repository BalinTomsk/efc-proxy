#include "proxy.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>

#include "breaker.hpp"
#include "clock_offset.hpp"
#include "cloud_range_store.hpp"
#include "day_key_store.hpp"
#include "jwt_verifier.hpp"
#include "log.hpp"
#include "user_prime_store.hpp"
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
    // Loaded best-effort: a missing/malformed day-key database must not take down the ungated GET
    // surface, so a load failure here just leaves this empty — every gated request then fails closed
    // (500) rather than the whole process refusing to start. See proxy_to_docapi's day-key gate.
    std::optional<DayKeyStore> daykey_store;
    // Per-account primes out of the RabbitMQ account mirror, used only to check a JWT's `user`
    // claim. Constructed only when CPROXY_JWT_REQUIRE_USER is on: the store is cheap but the mirror
    // it reads is optional infrastructure, and an unpopulated mirror matching nothing is exactly the
    // fail-closed behaviour that switch is asking for.
    std::optional<UserPrimeStore> user_prime_store;
    // Datacenter / cloud-provider ranges. Load failures leave this EMPTY, which blocks nothing —
    // the opposite of the day-key store's fail-closed stance, and deliberate: a missing range file
    // must never turn into "refuse all traffic". The frontend takes the same position by starting
    // with an empty table.
    CloudRangeStore owned_ranges;
    // Points at owned_ranges, or at a store the caller shares with the refresh thread.
    CloudRangeStore* cloud_ranges = &owned_ranges;
    // Correction applied to "now" when validating a credential, learned from admin requests. Starts
    // at zero (the host clock) on every start — see ClockOffset for why this is an in-process offset
    // and not the system clock.
    ClockOffset clock;

    explicit ProxyState(const Config& cfg, CloudRangeStore* shared_ranges)
        : breaker(cfg.breaker_threshold, std::chrono::milliseconds(cfg.breaker_cooldown_ms)) {
        if (shared_ranges != nullptr) cloud_ranges = shared_ranges;
        if (!cfg.daykey_db_path.empty()) {
            try {
                daykey_store.emplace(cfg.daykey_db_path);
                // Log the covered range: the store is date-keyed and finite, so this is the only
                // visible warning that it is running out. Past the last date every gated request
                // fails closed with the usual opaque 500 and nothing else says why.
                log_raw(std::format(
                    "{{\"service\":\"cproxy\",\"msg\":\"day-key store loaded\",\"days\":{},"
                    "\"from\":\"{}\",\"to\":\"{}\"}}",
                    daykey_store->size(), daykey_store->first_date(), daykey_store->last_date()));
            } catch (const std::exception& ex) {
                log_raw(std::format(
                    "{{\"service\":\"cproxy\",\"level\":\"ERROR\","
                    "\"msg\":\"day-key database failed to load, every gated request will 500: {}\"}}",
                    ex.what()));
            }
        }
        // Two consumers: the `user` claim check (CPROXY_JWT_REQUIRE_USER) and, since 0.12.0, the
        // admin lookup that gates clock alignment (CPROXY_JWT_CLOCK_SYNC). Either one needs the store;
        // with neither, it is never built and the mirror is never opened.
        const bool store_needed =
            cfg.jwt_enabled() && (cfg.jwt_require_user || cfg.jwt_clock_sync);
        if (store_needed && !cfg.account_mirror_db_path.empty()) {
            user_prime_store.emplace(cfg.account_mirror_db_path, cfg.jwt_user_cache_seconds);
            // Force the first snapshot here so a mirror that is missing, empty, or still dormant is
            // visible in the startup log rather than only as an unexplained wall of 500s. An empty
            // set is the fail-closed state, not an error the constructor can throw on.
            user_prime_store->refresh(std::chrono::system_clock::now());
            const std::string load_error = user_prime_store->last_error();
            // ERROR only where an empty store refuses traffic (REQUIRE_USER). For clock sync alone,
            // an empty store just means nobody may align the clock -- worth seeing, not an outage.
            const bool degraded = !load_error.empty() || user_prime_store->size() == 0;
            log_raw(std::format(
                "{{\"service\":\"cproxy\",\"level\":\"{}\",\"msg\":\"user-prime store loaded\","
                "\"accounts\":{},\"admins\":{},\"error\":\"{}\"}}",
                degraded ? (cfg.jwt_require_user ? "ERROR" : "WARN") : "INFO",
                user_prime_store->size(), user_prime_store->admin_count(), load_error));
        }
        if (!cfg.cloudrange_db_path.empty()) {
            try {
                cloud_ranges->reload(cfg.cloudrange_db_path);
                log_raw(std::format("{{\"service\":\"cproxy\",\"msg\":\"cloud-range store loaded\","
                                    "\"merged_ranges\":{}}}",
                                    cloud_ranges->size()));
            } catch (const std::exception& ex) {
                // A file that does not exist yet is the normal first-boot state (the refresher has
                // not run), not a fault — logging it at ERROR would train everyone to ignore the
                // line that also reports a genuinely corrupt or unreadable database.
                const bool absent = !std::filesystem::exists(cfg.cloudrange_db_path);
                log_raw(std::format(
                    "{{\"service\":\"cproxy\",\"level\":\"{}\",\"msg\":\"{}: {}\"}}",
                    absent ? "INFO" : "ERROR",
                    absent ? "no cloud-range database yet, nothing IP-blocked until the first "
                             "refresh"
                           : "cloud-range database failed to load, nothing will be IP-blocked",
                    ex.what()));
            }
        }
    }
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

/** Outcome of the gated-surface credential check: `ok`, plus a short reason for the LOG only. */
struct CredentialCheck {
    bool ok = false;
    std::string reason;
};

/**
 * The caller's own clock, from `X-Client-Time` (epoch seconds). False when the header is absent,
 * empty, non-numeric, or has trailing junk — a header we cannot read must never be treated as a
 * reading of zero, which would look like a 56-year skew.
 */
bool client_time_header(const httplib::Request& req, long long& out) {
    const std::string raw = req.get_header_value("X-Client-Time");
    if (raw.empty()) return false;
    const char* first = raw.data();
    const char* last = raw.data() + raw.size();
    long long value = 0;
    const auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc{} || ptr != last || value <= 0) return false;
    out = value;
    return true;
}

/**
 * Corrects this process's clock offset from a request, when the request is entitled to do that.
 * Returns true when the offset actually moved (so the caller knows to re-evaluate the token).
 *
 * Three conditions, all required, and the first two are the whole security argument:
 *   - the token's MAC verified AND its `user` product belongs, in THIS service's account mirror, to
 *     a live account with `access == 255` (superAdmin). The privilege is looked up here, never read
 *     from the token — an `adm` claim is ignored (0.12.0; see JwtClaims). So a signing-secret leak
 *     alone is not enough: the forger would also need a real admin's primes for today;
 *   - the request carries `X-Client-Time`, because the token's own `iat` is cached until UTC
 *     midnight and is therefore stale by design (see ClockOffset);
 *   - the gap exceeds the configured threshold.
 *
 * `ClockOffset::adopt` bounds the result, so the worst a replayed admin token can do is move this
 * process by `jwt_clock_sync_max_seconds`.
 */
bool align_clock_from_request(const Config& cfg, ProxyState& state, const httplib::Request& req,
                              const JwtResult& verified,
                              std::chrono::system_clock::time_point now) {
    if (!cfg.jwt_clock_sync || !verified.signature_ok) return false;
    // Only a token that is right about everything EXCEPT possibly the time. A malformed one (no
    // `exp`) is authentic but not understood, and is not evidence of anything about the clock.
    if (!verified.ok && !verified.time_rejected) return false;
    // The header check is cheap and rules out almost every request, so it runs before the store.
    long long client_epoch = 0;
    if (!client_time_header(req, client_epoch)) return false;
    // Looked up at `now` -- the clock being corrected. That is safe: the product is matched over a
    // yesterday/today/tomorrow window, and the offset is capped far below a day.
    if (verified.claims.user.empty() || !state.user_prime_store.has_value() ||
        !state.user_prime_store->is_admin(verified.claims.user, now)) {
        return false;
    }

    const long long now_epoch =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    const long long delta = client_epoch - now_epoch;
    if (std::llabs(delta) < cfg.jwt_clock_sync_threshold_seconds) return false;

    const long long before = state.clock.offset_seconds();
    if (!state.clock.adopt(delta, cfg.jwt_clock_sync_max_seconds)) {
        // Refused, or clamped to no change: the gap is real but correcting it fully would exceed the
        // ceiling. WARN, because at this point the host clock is wrong by more than an operator
        // should ever have to discover from a wall of 500s.
        log_raw(std::format(
            "{{\"service\":\"cproxy\",\"level\":\"WARN\",\"msg\":\"clock alignment refused\","
            "\"delta\":{},\"offset\":{},\"max\":{}}}",
            delta, before, cfg.jwt_clock_sync_max_seconds));
        return false;
    }
    log_raw(std::format(
        "{{\"service\":\"cproxy\",\"level\":\"WARN\",\"msg\":\"clock aligned from admin token\","
        "\"delta\":{},\"offset_was\":{},\"offset_now\":{}}}",
        delta, before, state.clock.offset_seconds()));
    return true;
}

/**
 * The credential for the gated surface: an `Authorization: Bearer <HS512 JWT>` whose `server` claim
 * carries the day-key and whose `user` claim carries this account's `Users.prime * Users_Prime.prime`
 * for today. It is the ONLY credential. The raw `X-Day-Guid` header that preceded it (0.6–0.9, and
 * accepted alongside the token until `CPROXY_JWT_REQUIRED` was turned on) was removed in 0.13.0; a
 * request carrying that header is judged exactly as one carrying nothing, so there is no switch left
 * that can put a bare day-key back into service.
 *
 * Rules worth stating, because each one is a decision rather than an accident:
 *
 * - **The day-key is checked from the token's `server` claim, never from a header.** The JWT proves
 *   the caller holds the signing secret; the claim proves they also hold today's rotating key.
 *   Dropping the second check would make a leaked signing secret permanent access, which is the
 *   exact property the day-key rotation exists to deny.
 * - **No secret configured means the gate is shut**, not open and not header-based: every gated
 *   request fails closed, exactly like a missing day-key store. The ungated GET surface is untouched.
 * - **The reason never reaches the caller.** Every failure here answers the same generic 500 (see
 *   proxy_to_docapi), so a prober cannot tell a bad signature from an expired token from an unknown
 *   account — or from an ordinary server error.
 */
CredentialCheck check_gate_credential(const Config& cfg, ProxyState& state,
                                      const httplib::Request& req,
                                      std::chrono::system_clock::time_point now) {
    if (!cfg.jwt_enabled()) return {false, "jwt not configured (CPROXY_JWT_SECRET unset)"};

    const std::string token = bearer_token(req.get_header_value("Authorization"));
    if (token.empty()) return {false, "no bearer token presented"};

    JwtVerifyOptions opts;
    opts.secret = cfg.jwt_secret;
    opts.issuer = cfg.jwt_issuer;
    opts.audience = cfg.jwt_audience;
    opts.subject = cfg.jwt_subject;
    opts.leeway_seconds = cfg.jwt_leeway_seconds;

    JwtResult verified = verify_hs512(token, opts, now);

    // An admin request may correct the clock — on a pass (keeping drift from ever growing into a
    // failure) as well as on a time-only rejection (recovering from one that already has). The
    // recovery arm re-verifies ONCE against the corrected clock; it cannot loop, because a second
    // alignment from the same request would compute a delta of zero.
    if (align_clock_from_request(cfg, state, req, verified, now)) {
        now = state.clock.now();
        verified = verify_hs512(token, opts, now);
    }

    if (!verified.ok) return {false, "jwt rejected: " + verified.error};

    if (!state.daykey_store.has_value() || !state.daykey_store->is_valid(verified.claims.server, now)) {
        return {false, "jwt server claim is not a current day-key"};
    }
    if (cfg.jwt_require_user) {
        // A WRITE must name an account; a gated READ need not. /news/featured and /news/more are the
        // home page, served to anonymous visitors, so demanding a `user` claim there would put the
        // whole front page behind a login — the gate exists to stop anonymous SCRAPING of an
        // expensive endpoint, not anonymous READING of it. Whenever a claim IS present it is checked,
        // read or write, so a stale or revoked account never rides along unnoticed.
        const bool is_write = iequals(req.method, "POST") || iequals(req.method, "PATCH");
        if (verified.claims.user.empty()) {
            if (is_write) return {false, "jwt carries no user claim on a write"};
        } else if (!state.user_prime_store.has_value() ||
                   !state.user_prime_store->is_valid(verified.claims.user, now)) {
            return {false, "jwt user claim does not match a live account"};
        }
    }
    return {true, {}};
}

/** Forwards one request to the docapi upstream and copies the response back. */
void proxy_to_docapi(const Config& cfg, ProxyState& state, const httplib::Request& req,
                     httplib::Response& res) {
    const std::string rid = request_id(req);
    res.set_header("X-Request-Id", rid);

    // Datacenter / cloud-provider block, first of all the guards — a request from hosting space is
    // refused before it can consume an upstream call, a day-key comparison, or anything else.
    //
    // The peer address is taken from req.remote_addr and NEVER from X-Forwarded-For: cproxy is the
    // edge, so remote_addr is the real TCP peer, while an inbound XFF is attacker-controlled and
    // trusting it would let anyone bypass the block by claiming a residential address (or get a
    // third party blocked by claiming theirs).
    //
    // Answered with the same opaque 500 as a failed day-key rather than 403: a caller probing the
    // gateway learns nothing about why it was refused. The frontend uses an opaque 404 for the same
    // reason; 500 is the convention already established here.
    if (cfg.cloudrange_block_enabled && !cfg.cloudrange_exempt(req.remote_addr) &&
        state.cloud_ranges->is_blocked(req.remote_addr)) {
        write_error(res, 500, "internal_error", "Internal error");
        log_request(std::format("{} {} -> 500 (datacenter ip)", req.method, req.path),
                    req.remote_addr, rid);
        return;
    }

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
    const std::string target_path = target.substr(0, target.find('?'));
    // Dot-dot segments must die here: the upstream may normalize them and escape the route prefix
    // (e.g. /api/../actuator on a Spring upstream). req.path is the decoded form (catches %2e%2e);
    // the raw target's path portion catches the plain form.
    //
    // This runs BEFORE the day-key gate below, and must stay there. The gate matches on the tail of
    // the path, so traversal cannot strip a gated suffix off — but it can ADD one past it:
    // /api/v1/news/default/../default ends in "/default", clears a tail match on "/news/default",
    // and still normalizes back to the gated endpoint at a Spring upstream. Rejecting dot-dot first
    // means no request that reaches the gate can be re-pointed after it.
    if (has_dotdot_segment(req.path) || has_dotdot_segment(target_path)) {
        write_error(res, 400, "bad_request", "Path traversal is not allowed");
        log_request(std::format("{} {} -> 400 (dot-dot path)", req.method, req.path),
                    req.remote_addr, rid);
        return;
    }

    // The write surface (POST, PATCH) plus any path in CPROXY_DAYKEY_PATHS additionally requires the
    // gateway credential — a Bearer JWT carrying the day-key in its `server` claim; see
    // check_gate_credential. Deliberately answered with a generic 500,
    // not 401/403: a wrong or missing credential must not read any differently from an ordinary
    // server error to a caller probing it.
    // POST joined PATCH here when docapi's regulation endpoints (insert, not just merge-patch) were
    // fronted through cproxy — every method that mutates docapi state must clear the same gate, not
    // just PATCH. The path arm came later, to put READ endpoints behind the same credential
    // (/news/default first): expensive to assemble, and nothing about GET makes free scraping of it
    // acceptable. Both the decoded path and the raw target are tested, and either one matching
    // gates the request — the union is the fail-secure direction.
    if (cfg.daykey_required(req.method, req.path) || cfg.daykey_gated_path(target_path)) {
        const CredentialCheck credential =
            check_gate_credential(cfg, state, req, state.clock.now());
        if (!credential.ok) {
            write_error(res, 500, "internal_error", "Internal error");
            log_request(std::format("{} {} -> 500 ({})", req.method, req.path, credential.reason),
                        req.remote_addr, rid);
            return;
        }
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
    // is_unforwardable drops Content-Type because the RESPONSE side reads it straight off the
    // upstream's own reply instead of copying it — but for the OUTBOUND request that means no
    // Content-Type crosses at all: `out` is a raw httplib::Request (not built via Client::Post,
    // which is what sets a default), so an inbound "application/json" body would otherwise arrive
    // upstream as text/plain and trip Spring's `consumes = APPLICATION_JSON_VALUE` on any write
    // endpoint. Set it explicitly from the inbound request when present.
    if (const std::string content_type = req.get_header_value("Content-Type"); !content_type.empty()) {
        out.set_header("Content-Type", content_type.c_str());
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

void install_routes(httplib::Server& server, const Config& cfg, CloudRangeStore* shared_ranges) {
    // Per-server state (breaker + counters), captured by value into every handler so it lives
    // exactly as long as they do. See ProxyState for why this is not a global.
    auto state = std::make_shared<ProxyState>(cfg, shared_ranges);

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
