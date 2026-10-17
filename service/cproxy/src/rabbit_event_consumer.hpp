#pragma once

#include <atomic>
#include <string>
#include <thread>

#include "config.hpp"

namespace cproxy {

/** Scheme, host and port of CPROXY_RABBITMQ_MANAGEMENT_URL (also used by the service status reporter). */
struct RabbitEndpoint {
    std::string scheme;
    std::string host;
    int port = 15671;
};

/** Throws std::runtime_error on a URL that is not http(s)://host[:port]. */
RabbitEndpoint parse_rabbit_endpoint(const std::string& url);

class RabbitEventConsumer {
public:
    explicit RabbitEventConsumer(Config cfg);
    ~RabbitEventConsumer();

    RabbitEventConsumer(const RabbitEventConsumer&) = delete;
    RabbitEventConsumer& operator=(const RabbitEventConsumer&) = delete;

    void start();
    void stop();

private:
    void run();

    Config cfg_;
    std::atomic<bool> stop_{false};
    std::thread worker_;
};

}  // namespace cproxy
