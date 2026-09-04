#pragma once

#include <atomic>
#include <thread>

#include "config.hpp"

namespace cproxy {

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
