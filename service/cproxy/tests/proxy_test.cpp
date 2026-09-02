// Integration tests: real HTTP through install_routes() against an in-process fake upstream.
// Framework-free like config_test; registered with CTest (also executed inside the Docker build).
#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <httplib.h>
#include <sqlite3.h>

#include "cloud_range_store.hpp"
#include "config.hpp"
#include "day_key_store.hpp"
#include "proxy.hpp"

using namespace cproxy;

namespace {

// Runs an httplib::Server on an ephemeral 127.0.0.1 port in a background thread.
struct TestServer {
    httplib::Server server;
    int port = 0;
    std::thread th;

    void start() {
        port = server.bind_to_any_port("127.0.0.1");
        CHECK(port > 0);
        th = std::thread([this] { server.listen_after_bind(); });
        server.wait_until_ready();
    }
    ~TestServer() {
        server.stop();
        if (th.joinable()) th.join();
    }
};

// Fake docapi: echoes the raw request target in the body and mirrors interesting request headers
// back as response headers so tests can assert what actually crossed the wire.
void install_fake_upstream(httplib::Server& s) {
    s.Get(R"(/.*)", [](const httplib::Request& req, httplib::Response& res) {
        res.set_header("X-Got-XFF", req.get_header_value("X-Forwarded-For"));
        res.set_header("X-Got-Reqid", req.get_header_value("X-Request-Id"));
        res.set_content("upstream:" + req.target, "text/plain");
    });
}

/**
 * A date-keyed day-key database covering a window around the CURRENT date, every row holding the
 * SAME guid — so `guid` is the valid key whenever the test runs. day_key_store_test covers which
 * row is picked for which date; this file only needs "a key that works today" to exercise the
 * proxy's gate. The window is generous so the test is immune to running across a UTC midnight.
 */
void write_uniform_day_key_db(const std::string& path, const std::string& guid) {
    std::remove(path.c_str());
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE day_keys (stamp TEXT PRIMARY KEY, guid TEXT NOT NULL)",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "INSERT INTO day_keys (stamp, guid) VALUES (?, ?)", -1, &stmt,
                             nullptr) == SQLITE_OK);
    const auto today = std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now());
    for (int offset = -3; offset <= 3; ++offset) {
        const std::string stamp = utc_date_string(today + std::chrono::days{offset});
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, stamp.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, guid.c_str(), -1, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(stmt) == SQLITE_DONE);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void health_is_local() {
    Config cfg;  // upstream irrelevant for /health
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto r = cli.Get("/health");
    CHECK(r && r->status == 200);
    CHECK(r->body.find("\"status\":\"UP\"") != std::string::npos);
}

void forwards_raw_target_and_provenance_headers() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto r = cli.Get("/api/echo?q=a%20b&x=1");
    CHECK(r && r->status == 200);
    // The target must cross the proxy VERBATIM - no decode/re-encode round trip.
    CHECK(r->body == "upstream:/api/echo?q=a%20b&x=1");
    CHECK(r->get_header_value("X-Got-XFF") == "127.0.0.1");
}

void request_id_is_issued_and_propagated() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    // No inbound id: the proxy must mint one, send it upstream, and echo it to the caller.
    auto r = cli.Get("/api/thing");
    CHECK(r && r->status == 200);
    const std::string minted = r->get_header_value("X-Request-Id");
    CHECK(!minted.empty());
    CHECK(r->get_header_value("X-Got-Reqid") == minted);

    // A well-formed caller-supplied id is preserved end to end.
    auto r2 = cli.Get("/api/thing", {{"X-Request-Id", "abc-123"}});
    CHECK(r2 && r2->status == 200);
    CHECK(r2->get_header_value("X-Request-Id") == "abc-123");
    CHECK(r2->get_header_value("X-Got-Reqid") == "abc-123");

    // A junk id (bad charset) is replaced, never forwarded verbatim.
    auto r3 = cli.Get("/api/thing", {{"X-Request-Id", "evil\"chars<>"}});
    CHECK(r3 && r3->status == 200);
    CHECK(r3->get_header_value("X-Got-Reqid") != "evil\"chars<>");
    CHECK(!r3->get_header_value("X-Got-Reqid").empty());
}

void dotdot_paths_are_rejected() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    // Plain, percent-encoded, and nested dot-dot must all die at the proxy with 400 - the upstream
    // may normalize them and escape the route prefix (e.g. /api/../actuator on a Spring upstream).
    auto r1 = cli.Get("/api/../secret");
    CHECK(r1 && r1->status == 400);
    auto r2 = cli.Get("/api/%2e%2e/secret");
    CHECK(r2 && r2->status == 400);
    auto r3 = cli.Get("/api/x/../../secret");
    CHECK(r3 && r3->status == 400);

    // Dots INSIDE a segment are legitimate and must still pass.
    auto ok = cli.Get("/api/file.name.json");
    CHECK(ok && ok->status == 200);
    CHECK(ok->body == "upstream:/api/file.name.json");
}

void api_key_and_method_guards() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    cfg.api_key = "k-42";
    cfg.allowed_methods = {"GET"};
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto no_key = cli.Get("/api/thing");
    CHECK(no_key && no_key->status == 401);
    auto bad_key = cli.Get("/api/thing", {{"X-API-Key", "wrong"}});
    CHECK(bad_key && bad_key->status == 401);
    auto good = cli.Get("/api/thing", {{"X-API-Key", "k-42"}});
    CHECK(good && good->status == 200);
    auto post = cli.Post("/api/thing", "body", "text/plain");
    CHECK(post && post->status == 405);  // method is checked before the key
}

void oversized_body_is_rejected() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    cfg.max_payload_bytes = 1024;  // tiny limit so the test payload stays small
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    // The fake upstream flags any request it sees so we can prove the body never got through.
    bool upstream_reached = false;
    up.server.Post(R"(/.*)", [&](const httplib::Request&, httplib::Response& res) {
        upstream_reached = true;
        res.set_content("should never happen", "text/plain");
    });

    httplib::Client cli("127.0.0.1", proxy.port);
    const std::string big(2048, 'x');
    auto r = cli.Post("/api/thing", big, "text/plain");
    CHECK(r && r->status == 413);  // cut off while reading, before any handler runs...
    CHECK(!upstream_reached);      // ...so the body never reaches the upstream.
}

void request_bodies_are_forwarded() {
    TestServer up;
    // PUT, not POST: POST now also requires the day-key gate (see day_key_store_test.cpp and
    // post_and_patch_require_day_key below), which is irrelevant to what this test is checking and
    // would need its own SQLite fixture to pass.
    up.server.Put(R"(/.*)", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content("got:" + req.body, "text/plain");  // echo proves the body crossed the proxy
    });
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto r = cli.Put("/api/submit", "hello-body", "text/plain");
    CHECK(r && r->status == 200);
    CHECK(r->body == "got:hello-body");  // a pre-routing proxy would forward an EMPTY body
}

// Regression: is_unforwardable() drops Content-Type on purpose for the RESPONSE side (the upstream's
// own header is used there instead), but the outbound REQUEST is a raw httplib::Request built by
// hand, not via Client::Post/Patch — nothing else sets Content-Type on it. Before this test existed,
// a JSON body crossed the proxy as text/plain and tripped `consumes = APPLICATION_JSON_VALUE` on any
// Spring write endpoint (found live: docapi's PATCH /river/fish/{guid} 500'd through cproxy on its
// first real deploy while working fine called directly).
void content_type_is_forwarded() {
    // PUT, not POST/PATCH: both of those now require the day-key gate (see day_key_store_test.cpp
    // and post_and_patch_require_day_key below), which is irrelevant to what this test is checking
    // and would need its own SQLite fixture to pass.
    TestServer up;
    up.server.Put(R"(/.*)", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content(req.get_header_value("Content-Type"), "text/plain");
    });
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto r = cli.Put("/api/river/fish/x", "[]", "application/json");
    CHECK(r && r->status == 200);
    CHECK(r->body == "application/json");  // the upstream must see it, not a default/missing value
}

// The write surface's day-key gate (see proxy_to_docapi) now covers POST as well as PATCH, since
// docapi's regulation endpoints add a genuine insert (POST), not just merge-patch (PATCH). Neither
// method reaches the upstream without a configured day-key store — this proves both fail closed
// (500, the same generic error a wrong/missing X-Day-Guid produces) rather than silently falling
// back to PATCH-only gating.
void post_and_patch_require_day_key() {
    TestServer up;
    install_fake_upstream(up.server);
    up.server.Post(R"(/.*)", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("should not be reached", "text/plain");
    });
    up.server.Patch(R"(/.*)", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("should not be reached", "text/plain");
    });
    up.start();

    Config cfg;  // no daykey_db_path -- day-key store never gets configured
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto post = cli.Post("/api/river/regulation/x", "{}", "application/json");
    CHECK(post && post->status == 500);
    CHECK(post->body.find("internal_error") != std::string::npos);

    auto patch = cli.Patch("/api/river/fish/x", "[]", "application/json");
    CHECK(patch && patch->status == 500);
    CHECK(patch->body.find("internal_error") != std::string::npos);
}

// GET /news/default is day-key gated by config default: the credential is no longer only about
// mutating state, it also fences off a read that is expensive to assemble upstream. Everything here
// is a GET, so nothing in the method arm of the gate is doing the work.
void gated_read_path_requires_day_key() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    const std::string db = "proxy_test_day_keys.sqlite";
    write_uniform_day_key_db(db, "TEST-DAY-KEY");

    Config cfg;  // daykey_paths defaults to {"/news/default"}
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    cfg.daykey_db_path = db;
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);

    // No key, wrong key: the generic 500, indistinguishable from an ordinary server error.
    auto bare = cli.Get("/api/v1/news/default");
    CHECK(bare && bare->status == 500);
    CHECK(bare->body.find("internal_error") != std::string::npos);
    CHECK(bare->body.find("day") == std::string::npos);  // the reason must not leak into the body
    auto wrong = cli.Get("/api/v1/news/default", {{"X-Day-Guid", "nope"}});
    CHECK(wrong && wrong->status == 500);

    // The current day's key gets through, and the request still reaches the upstream intact.
    auto ok = cli.Get("/api/v1/news/default", {{"X-Day-Guid", "TEST-DAY-KEY"}});
    CHECK(ok && ok->status == 200);
    CHECK(ok->body == "upstream:/api/v1/news/default");

    // Trailing slash, casing, a query string, and a nested sub-path are all still gated.
    CHECK(cli.Get("/api/v1/news/default/")->status == 500);
    CHECK(cli.Get("/api/v1/News/Default")->status == 500);
    CHECK(cli.Get("/api/v1/news/default?country=CA")->status == 500);
    CHECK(cli.Get("/api/v1/news/default/extra")->status == 500);

    // Traversal must not be able to re-point a request past the gate: the tail here is "/default",
    // which would clear a naive suffix match, but a Spring upstream normalizes it straight back to
    // the gated endpoint. The dot-dot rejection runs first, so it never reaches the gate at all.
    auto dodge = cli.Get("/api/v1/news/default/../default");
    CHECK(dodge && dodge->status == 400);

    // Sibling news reads are untouched — no key, still served.
    auto list = cli.Get("/api/v1/news/list?country=CA");
    CHECK(list && list->status == 200);
    CHECK(list->body == "upstream:/api/v1/news/list?country=CA");
    auto fish = cli.Get("/api/v1/fish?water=fresh");
    CHECK(fish && fish->status == 200);

    std::remove(db.c_str());
}

// Turning the path gate off (CPROXY_DAYKEY_PATHS=NONE) must actually open the read back up,
// otherwise there is no way to roll the protection back without shipping a new binary.
void gated_read_path_can_be_disabled() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    cfg.daykey_paths.clear();  // what CPROXY_DAYKEY_PATHS=NONE produces
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto r = cli.Get("/api/v1/news/default");
    CHECK(r && r->status == 200);
    CHECK(r->body == "upstream:/api/v1/news/default");
}

// A REST call from datacenter space is refused with 500 before anything else runs. The tests
// connect over loopback, so 127.0.0.1 is the peer address and the range under test has to cover it
// — every other address here is an RFC 5737 documentation one.
void datacenter_ip_is_refused_with_500() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    cfg.daykey_paths.clear();  // isolate this from the day-key gate

    CloudRangeStore ranges;
    ranges.replace({{*parse_ipv4("127.0.0.0"), *parse_ipv4("127.0.0.255")}});

    TestServer proxy;
    install_routes(proxy.server, cfg, &ranges);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto blocked = cli.Get("/api/v1/fish");
    CHECK(blocked && blocked->status == 500);
    CHECK(blocked->body.find("internal_error") != std::string::npos);
    // The reason must not leak — a caller probing the gateway cannot tell this from a real fault.
    CHECK(blocked->body.find("datacenter") == std::string::npos);
    CHECK(blocked->body.find("ip") == std::string::npos);

    // It runs BEFORE the method allow-list: a disallowed method from a blocked IP still reads as
    // 500, not 405, so the block cannot be probed by watching which methods answer differently.
    Config restricted = cfg;
    restricted.allowed_methods = {"GET"};
    TestServer proxy2;
    install_routes(proxy2.server, restricted, &ranges);
    proxy2.start();
    httplib::Client cli2("127.0.0.1", proxy2.port);
    auto post = cli2.Post("/api/v1/fish", "x", "text/plain");
    CHECK(post && post->status == 500);
}

// Three independent escape hatches, because a wrong range here takes the portal offline: the
// kill-switch, the exempt list, and an empty store.
void datacenter_block_has_escape_hatches() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();
    const std::string upstream = "http://127.0.0.1:" + std::to_string(up.port);

    CloudRangeStore ranges;
    ranges.replace({{*parse_ipv4("127.0.0.0"), *parse_ipv4("127.0.0.255")}});

    // 1. CPROXY_BLOCK_CLOUD_IPS=false — ranges still loaded, nothing refused.
    {
        Config cfg;
        cfg.docapi_upstream = upstream;
        cfg.daykey_paths.clear();
        cfg.cloudrange_block_enabled = false;
        TestServer proxy;
        install_routes(proxy.server, cfg, &ranges);
        proxy.start();
        httplib::Client cli("127.0.0.1", proxy.port);
        auto r = cli.Get("/api/v1/fish");
        CHECK(r && r->status == 200);
    }

    // 2. The exempt list. external_frontend is exempt automatically: the portal's own host sits at
    //    a hosting provider, so without this the block would take the site down.
    {
        Config cfg;
        cfg.docapi_upstream = upstream;
        cfg.daykey_paths.clear();
        cfg.external_frontend = "127.0.0.1";
        CHECK(cfg.cloudrange_exempt("127.0.0.1"));
        TestServer proxy;
        install_routes(proxy.server, cfg, &ranges);
        proxy.start();
        httplib::Client cli("127.0.0.1", proxy.port);
        auto r = cli.Get("/api/v1/fish");
        CHECK(r && r->status == 200);
    }

    // 3. An empty store blocks nothing — the state after a failed load or before the first refresh.
    {
        Config cfg;
        cfg.docapi_upstream = upstream;
        cfg.daykey_paths.clear();
        CloudRangeStore empty;
        TestServer proxy;
        install_routes(proxy.server, cfg, &empty);
        proxy.start();
        httplib::Client cli("127.0.0.1", proxy.port);
        auto r = cli.Get("/api/v1/fish");
        CHECK(r && r->status == 200);
    }
}

void upstream_down_is_502_and_unknown_path_is_404() {
    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:1";  // nothing listens there
    cfg.connect_timeout_ms = 300;                // keep the failing test fast
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto r = cli.Get("/api/thing");
    CHECK(r && r->status == 502);
    CHECK(r->body.find("bad_gateway") != std::string::npos);

    auto nf = cli.Get("/nope");
    CHECK(nf && nf->status == 404);
    CHECK(nf->body.find("not_found") != std::string::npos);
}

void ready_reports_upstream_state_and_breaker_fails_fast() {
    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:1";  // nothing listens there
    cfg.connect_timeout_ms = 300;
    cfg.breaker_threshold = 2;
    cfg.breaker_cooldown_ms = 60000;  // long enough that the test never leaves the open state
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    cli.set_read_timeout(5, 0);

    // Healthy on arrival: liveness and readiness both green before anything has failed.
    auto live = cli.Get("/health");
    CHECK(live && live->status == 200);
    auto ready0 = cli.Get("/health/ready");
    CHECK(ready0 && ready0->status == 200);
    CHECK(ready0->body.find("\"upstream\":\"closed\"") != std::string::npos);

    // Two transport failures trip the breaker.
    for (int i = 0; i < 2; ++i) {
        auto r = cli.Get("/api/thing");
        CHECK(r && r->status == 502);
    }

    // Now it must fail fast: no connect attempt, so the response beats the connect timeout easily.
    const auto started = std::chrono::steady_clock::now();
    auto fast = cli.Get("/api/thing");
    const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - started)
                          .count();
    CHECK(fast && fast->status == 502);
    CHECK(fast->body.find("upstream_unavailable") != std::string::npos);
    CHECK(took < 200);  // the 300ms connect timeout was never paid

    // Readiness flips to 503 while the breaker is open; liveness stays 200 (the proxy is alive).
    auto ready1 = cli.Get("/health/ready");
    CHECK(ready1 && ready1->status == 503);
    CHECK(ready1->body.find("\"upstream\":\"open\"") != std::string::npos);
    auto live1 = cli.Get("/health");
    CHECK(live1 && live1->status == 200);
}

void metrics_expose_counters() {
    TestServer up;
    install_fake_upstream(up.server);
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    CHECK(cli.Get("/api/one"));
    CHECK(cli.Get("/api/two"));
    cli.Get("/nope");  // a 404 must be counted too

    auto m = cli.Get("/metrics");
    CHECK(m && m->status == 200);
    CHECK(m->body.find("cproxy_requests_total{status=\"200\"} 2") != std::string::npos);
    CHECK(m->body.find("cproxy_requests_total{status=\"404\"} 1") != std::string::npos);
    CHECK(m->body.find("cproxy_upstream_latency_ms_count 2") != std::string::npos);
    CHECK(m->body.find("cproxy_breaker_state 0") != std::string::npos);
    // Metrics must not be forwarded upstream, and must not count themselves as proxied traffic.
    CHECK(m->body.find("upstream:/metrics") == std::string::npos);
}

void upstream_connection_is_reused_across_requests() {
    TestServer up;
    // Count distinct upstream TCP connections: httplib gives each accepted socket its own
    // remote port, so a reused keep-alive connection shows the SAME port for every request.
    std::set<std::string> peers;
    std::mutex peers_mu;
    up.server.Get(R"(/.*)", [&](const httplib::Request& req, httplib::Response& res) {
        {
            std::lock_guard<std::mutex> lock(peers_mu);
            peers.insert(std::to_string(req.remote_port));
        }
        res.set_content("ok", "text/plain");
    });
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    // One client => one proxy worker thread => one pooled upstream connection for all 5 requests.
    httplib::Client cli("127.0.0.1", proxy.port);
    cli.set_keep_alive(true);
    for (int i = 0; i < 5; ++i) {
        auto r = cli.Get("/api/thing");
        CHECK(r && r->status == 200);
    }
    std::lock_guard<std::mutex> lock(peers_mu);
    CHECK(peers.size() == 1);  // pre-0.5.0 this was 5 - a fresh connection per request
}

}  // namespace

int main() {
    health_is_local();
    forwards_raw_target_and_provenance_headers();
    request_id_is_issued_and_propagated();
    dotdot_paths_are_rejected();
    api_key_and_method_guards();
    oversized_body_is_rejected();
    request_bodies_are_forwarded();
    content_type_is_forwarded();
    post_and_patch_require_day_key();
    gated_read_path_requires_day_key();
    gated_read_path_can_be_disabled();
    datacenter_ip_is_refused_with_500();
    datacenter_block_has_escape_hatches();
    upstream_down_is_502_and_unknown_path_is_404();
    ready_reports_upstream_state_and_breaker_fails_fast();
    metrics_expose_counters();
    upstream_connection_is_reused_across_requests();
    std::cout << "proxy_test: all assertions passed\n";
    return 0;
}
