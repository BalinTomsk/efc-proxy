// Unit tests for the service status message, the route family shown on the admin page, and the
// reporter's on-switch. Registered with CTest.
#include "check.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <iostream>
#include <map>
#include <string>

#include "config.hpp"
#include "service_status.hpp"
#include "version.hpp"

using namespace cproxy;

namespace {

EnvLookup make_env(std::map<std::string, std::string> m) {
    return [m = std::move(m)](const char* key) -> std::optional<std::string> {
        auto it = m.find(key);
        if (it == m.end()) return std::nullopt;
        return it->second;
    };
}

void route_family_keeps_three_segments_and_drops_ids() {
    CHECK(route_family("/api/v1/river/0b2f-guid") == "/api/v1/river");
    CHECK(route_family("/api/v1/news/list?country=CA") == "/api/v1/news");
    CHECK(route_family("/api/v1/news") == "/api/v1/news");
    CHECK(route_family("/health") == "/health");
}

void body_follows_the_contract() {
    using namespace std::chrono;
    const sys_seconds start = sys_days{year{2026} / 10 / 16} + hours{12};
    const sys_seconds sent = start + minutes{65};
    const ServiceActivity::Last last{start + minutes{64}, "GET /api/v1/river -> docapi"};

    const auto body = nlohmann::json::parse(service_status_body("heartbeat", "cproxy-droplet", start, sent, last));

    CHECK(body["type"] == "fishfind.service-status.v1");
    CHECK(body["event"] == "heartbeat");
    CHECK(body["service"] == "cproxy");
    CHECK(body["machine"] == "cproxy-droplet");
    CHECK(body["version"] == CPROXY_VERSION);
    CHECK(body["processStartUtc"] == "2026-10-16T12:00:00Z");
    CHECK(body["sentUtc"] == "2026-10-16T13:05:00Z");
    CHECK(body["lastActionUtc"] == "2026-10-16T13:04:00Z");
    CHECK(body["lastAction"] == "GET /api/v1/river -> docapi");
}

void body_without_activity_sends_nulls() {
    const auto now = std::chrono::system_clock::now();
    const auto body = nlohmann::json::parse(service_status_body("start", "h", now, now, std::nullopt));
    CHECK(body["lastAction"].is_null());
    CHECK(body["lastActionUtc"].is_null());
}

void reporting_needs_https_broker_and_credentials() {
    const std::map<std::string, std::string> on = {{"CPROXY_RABBITMQ_MANAGEMENT_URL", "https://mq.example.test"},
                                                   {"CPROXY_RABBITMQ_USERNAME", "u"},
                                                   {"CPROXY_RABBITMQ_PASSWORD", "p"},
                                                   {"CPROXY_STATUS_MACHINE", "cproxy-droplet"}};
    Config c = load_config(make_env(on));
    CHECK(c.status_reporting());
    CHECK(c.status_machine == "cproxy-droplet");
    CHECK(c.status_interval_s == 60);

    auto off = on;
    off["CPROXY_STATUS_ENABLED"] = "false";
    CHECK(!load_config(make_env(off)).status_reporting());

    auto plain = on;
    plain["CPROXY_RABBITMQ_MANAGEMENT_URL"] = "http://mq.example.test";
    CHECK(!load_config(make_env(plain)).status_reporting());

    CHECK(!load_config(make_env({})).status_reporting());
}

void activity_keeps_the_latest() {
    ServiceActivity activity;
    CHECK(!activity.last().has_value());
    activity.record("a");
    activity.record("b");
    CHECK(activity.last()->action == "b");
}

}  // namespace

int main() {
    route_family_keeps_three_segments_and_drops_ids();
    body_follows_the_contract();
    body_without_activity_sends_nulls();
    reporting_needs_https_broker_and_credentials();
    activity_keeps_the_latest();
    std::cout << "service_status_test: all assertions passed\n";
    return 0;
}
