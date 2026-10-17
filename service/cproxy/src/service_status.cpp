#include "service_status.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <format>

#include "log.hpp"
#include "rabbit_event_consumer.hpp"
#include "version.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <unistd.h>
#endif

namespace cproxy {
namespace {

constexpr const char* kMessageType = "fishfind.service-status.v1";
constexpr const char* kQueue = "fishfind.servicestatus.events";

const std::chrono::system_clock::time_point kProcessStart = std::chrono::system_clock::now();

std::string iso_utc(std::chrono::system_clock::time_point tp) {
    return std::format("{:%FT%TZ}", std::chrono::floor<std::chrono::seconds>(tp));
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string host_name() {
    char buf[256] = {};
    if (gethostname(buf, sizeof(buf) - 1) == 0 && buf[0] != '\0') return buf;
    return "unknown";
}

}  // namespace

void ServiceActivity::record(std::string action) {
    std::lock_guard lock(mu_);
    last_ = Last{std::chrono::system_clock::now(), std::move(action)};
}

std::optional<ServiceActivity::Last> ServiceActivity::last() const {
    std::lock_guard lock(mu_);
    return last_;
}

ServiceActivity& service_activity() {
    static ServiceActivity activity;
    return activity;
}

std::string route_family(const std::string& path) {
    std::string clean = path.substr(0, path.find_first_of("?#"));
    std::size_t pos = 0;
    for (int segments = 0; segments < 3; ++segments) {
        const std::size_t next = clean.find('/', pos + 1);
        if (next == std::string::npos) return clean;
        pos = next;
    }
    return clean.substr(0, pos);
}

std::string service_status_body(const std::string& event, const std::string& machine,
                                std::chrono::system_clock::time_point process_start,
                                std::chrono::system_clock::time_point sent,
                                const std::optional<ServiceActivity::Last>& last) {
    nlohmann::json body = {
        {"type", kMessageType},
        {"event", event},
        {"service", "cproxy"},
        {"machine", machine},
        {"version", CPROXY_VERSION},
        {"processStartUtc", iso_utc(process_start)},
        {"sentUtc", iso_utc(sent)},
        {"lastActionUtc", last ? nlohmann::json(iso_utc(last->at)) : nlohmann::json(nullptr)},
        {"lastAction", last ? nlohmann::json(last->action) : nlohmann::json(nullptr)},
    };
    return body.dump();
}

ServiceStatusReporter::ServiceStatusReporter(Config cfg)
    : cfg_(std::move(cfg)), machine_(lower(cfg_.status_machine.empty() ? host_name() : cfg_.status_machine)) {}

ServiceStatusReporter::~ServiceStatusReporter() { stop(); }

void ServiceStatusReporter::start() {
    if (!cfg_.status_reporting()) {
        log_raw("{\"service\":\"cproxy\",\"msg\":\"Service status reporting off\"}");
        return;
    }
    stop_ = false;
    worker_ = std::thread([this] { run(); });
}

void ServiceStatusReporter::stop() {
    if (!worker_.joinable()) return;
    {
        std::lock_guard lock(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    worker_.join();
    publish("stop");
}

void ServiceStatusReporter::run() {
    log_raw(std::format("{{\"service\":\"cproxy\",\"msg\":\"Service status reporting on\",\"queue\":\"{}\","
                        "\"machine\":\"{}\"}}", kQueue, machine_));
    std::string event = "start";
    const auto interval = std::chrono::seconds(cfg_.status_interval_seconds());
    while (!stop_) {
        publish(event);
        event = "heartbeat";
        std::unique_lock lock(mu_);
        cv_.wait_for(lock, interval, [this] { return stop_.load(); });
    }
}

void ServiceStatusReporter::publish(const std::string& event) {
    try {
        const RabbitEndpoint endpoint = parse_rabbit_endpoint(cfg_.rabbitmq_management_url);
        httplib::SSLClient client(endpoint.host, endpoint.port);
        client.enable_server_certificate_verification(true);
        client.set_basic_auth(cfg_.rabbitmq_username, cfg_.rabbitmq_password);
        client.set_connection_timeout(5, 0);
        client.set_read_timeout(5, 0);

        nlohmann::json envelope = {
            {"properties", {{"delivery_mode", 1}, {"content_type", "application/json"}}},
            {"routing_key", kQueue},
            {"payload", service_status_body(event, machine_, kProcessStart, std::chrono::system_clock::now(),
                                            service_activity().last())},
            {"payload_encoding", "string"},
        };
        auto res = client.Post("/api/exchanges/%2F/amq.default/publish", envelope.dump(), "application/json");
        if (!res || res->status < 200 || res->status >= 300) {
            throw std::runtime_error(std::format("status {}", res ? res->status : 0));
        }
        warned_ = false;
    } catch (const std::exception& ex) {
        if (!warned_) {
            log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"WARN\",\"msg\":\"Service status not published\","
                                "\"event\":\"{}\",\"error\":\"{}\"}}", event, ex.what()));
            warned_ = true;
        }
    }
}

}  // namespace cproxy
