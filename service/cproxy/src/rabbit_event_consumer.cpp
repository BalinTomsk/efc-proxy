#include "rabbit_event_consumer.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <format>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

#include "account_mirror_store.hpp"
#include "log.hpp"

namespace cproxy {
namespace {

struct RabbitEndpoint {
    std::string scheme;
    std::string host;
    int port = 15671;
};

RabbitEndpoint parse_endpoint(const std::string& url) {
    RabbitEndpoint out;
    std::string rest;
    if (url.rfind("https://", 0) == 0) {
        out.scheme = "https";
        rest = url.substr(8);
        out.port = 443;
    } else if (url.rfind("http://", 0) == 0) {
        out.scheme = "http";
        rest = url.substr(7);
        out.port = 80;
    } else {
        throw std::runtime_error("CPROXY_RABBITMQ_MANAGEMENT_URL must start with http:// or https://");
    }
    const auto slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    const auto colon = rest.rfind(':');
    if (colon != std::string::npos) {
        out.host = rest.substr(0, colon);
        out.port = std::stoi(rest.substr(colon + 1));
    } else {
        out.host = rest;
    }
    if (out.host.empty() || out.port < 1 || out.port > 65535) {
        throw std::runtime_error("CPROXY_RABBITMQ_MANAGEMENT_URL has an invalid host or port");
    }
    return out;
}

std::string queue_path(const std::string& queue) {
    return "/api/queues/%2F/" + httplib::detail::encode_url(queue);
}

std::unique_ptr<httplib::SSLClient> make_client(const RabbitEndpoint& ep, const Config& cfg) {
    if (ep.scheme != "https") {
        throw std::runtime_error("RabbitMQ management API must use https:// in production");
    }
    auto client = std::make_unique<httplib::SSLClient>(ep.host, ep.port);
    client->enable_server_certificate_verification(true);
    client->set_basic_auth(cfg.rabbitmq_username, cfg.rabbitmq_password);
    client->set_connection_timeout(0, cfg.connect_timeout_ms * 1000);
    client->set_read_timeout(0, cfg.read_timeout_ms * 1000);
    return client;
}

void ensure_queue(httplib::SSLClient& client, const Config& cfg) {
    const std::string body = R"({"durable":true,"auto_delete":false,"arguments":{}})";
    auto res = client.Put(queue_path(cfg.rabbitmq_queue), body, "application/json");
    if (!res || (res->status < 200 || res->status >= 300)) {
        throw std::runtime_error(std::format("RabbitMQ queue declare failed with status {}",
                                             res ? res->status : 0));
    }
}

}  // namespace

RabbitEventConsumer::RabbitEventConsumer(Config cfg) : cfg_(std::move(cfg)) {}

RabbitEventConsumer::~RabbitEventConsumer() { stop(); }

void RabbitEventConsumer::start() {
    if (!cfg_.rabbitmq_events_enabled) return;
    stop_ = false;
    worker_ = std::thread([this] { run(); });
}

void RabbitEventConsumer::stop() {
    stop_ = true;
    if (worker_.joinable()) worker_.join();
}

void RabbitEventConsumer::run() {
    try {
        AccountMirrorStore store(cfg_.account_mirror_db_path);
        store.ensure_schema();
        const RabbitEndpoint endpoint = parse_endpoint(cfg_.rabbitmq_management_url);
        auto client = make_client(endpoint, cfg_);
        ensure_queue(*client, cfg_);

        log_raw(std::format("{{\"service\":\"cproxy\",\"msg\":\"RabbitMQ account-event consumer started\","
                            "\"queue\":\"{}\",\"sqlite\":\"{}\"}}",
                            cfg_.rabbitmq_queue, cfg_.account_mirror_db_path));

        while (!stop_) {
            nlohmann::json request = {
                {"count", cfg_.rabbitmq_batch_size},
                {"ackmode", "ack_requeue_false"},
                {"encoding", "auto"},
                {"truncate", 100000}
            };
            auto res = client->Post(queue_path(cfg_.rabbitmq_queue) + "/get", request.dump(), "application/json");
            if (!res || res->status < 200 || res->status >= 300) {
                log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"WARN\","
                                    "\"msg\":\"RabbitMQ account-event poll failed\",\"status\":{}}}",
                                    res ? res->status : 0));
                std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.rabbitmq_poll_ms));
                continue;
            }

            const auto messages = nlohmann::json::parse(res->body);
            if (!messages.is_array() || messages.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.rabbitmq_poll_ms));
                continue;
            }

            int applied = 0;
            for (const auto& message : messages) {
                try {
                    std::string payload = message.value("payload", "");
                    if (payload.empty()) continue;
                    nlohmann::json event = nlohmann::json::parse(payload);
                    if (store.apply_event(event)) ++applied;
                } catch (const std::exception& ex) {
                    log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"WARN\","
                                        "\"msg\":\"RabbitMQ account event rejected\",\"error\":\"{}\"}}",
                                        ex.what()));
                }
            }
            if (applied > 0) {
                log_raw(std::format("{{\"service\":\"cproxy\",\"msg\":\"RabbitMQ account events applied\","
                                    "\"count\":{}}}", applied));
            }
        }
    } catch (const std::exception& ex) {
        log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"ERROR\","
                            "\"msg\":\"RabbitMQ account-event consumer stopped\",\"error\":\"{}\"}}",
                            ex.what()));
    }
}

}  // namespace cproxy

