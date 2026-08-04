// Integration tests: real HTTP through install_routes() against an in-process fake upstream.
// Framework-free like config_test; registered with CTest (also executed inside the Docker build).
#include "check.hpp"
#include <iostream>
#include <string>
#include <thread>

#include <httplib.h>

#include "config.hpp"
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
    up.server.Post(R"(/.*)", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content("got:" + req.body, "text/plain");  // echo proves the body crossed the proxy
    });
    up.start();

    Config cfg;
    cfg.docapi_upstream = "http://127.0.0.1:" + std::to_string(up.port);
    TestServer proxy;
    install_routes(proxy.server, cfg);
    proxy.start();

    httplib::Client cli("127.0.0.1", proxy.port);
    auto r = cli.Post("/api/submit", "hello-body", "text/plain");
    CHECK(r && r->status == 200);
    CHECK(r->body == "got:hello-body");  // a pre-routing proxy would forward an EMPTY body
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

}  // namespace

int main() {
    health_is_local();
    forwards_raw_target_and_provenance_headers();
    request_id_is_issued_and_propagated();
    dotdot_paths_are_rejected();
    api_key_and_method_guards();
    oversized_body_is_rejected();
    request_bodies_are_forwarded();
    upstream_down_is_502_and_unknown_path_is_404();
    std::cout << "proxy_test: all assertions passed\n";
    return 0;
}
