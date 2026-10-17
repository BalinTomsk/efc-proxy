#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "config.hpp"

namespace cproxy {

/**
 * The newest request cproxy forwarded, for the admin status page: "GET /api/v1/river -> docapi" (the first
 * three path segments and the upstream, never ids or query strings). Recorded on every forwarded request;
 * the reporter sends only the latest with its next heartbeat.
 */
class ServiceActivity {
public:
    struct Last {
        std::chrono::system_clock::time_point at;
        std::string action;
    };

    void record(std::string action);
    std::optional<Last> last() const;

private:
    mutable std::mutex mu_;
    std::optional<Last> last_;
};

/** Process-wide activity, shared by the proxy routes and the reporter. */
ServiceActivity& service_activity();

/** "/api/v1/river/abc-123?x=1" -> "/api/v1/river": the route family, safe to show on the page. */
std::string route_family(const std::string& path);

/** One fishfind.service-status.v1 message body (UTC ISO-8601 times). */
std::string service_status_body(const std::string& event, const std::string& machine,
                                std::chrono::system_clock::time_point process_start,
                                std::chrono::system_clock::time_point sent,
                                const std::optional<ServiceActivity::Last>& last);

/**
 * Publishes cproxy's status to fishfind.servicestatus.events through the RabbitMQ management API (the same
 * broker and credentials as the account mirror): start once, a heartbeat every status_interval_s, stop on a
 * clean shutdown. efcs-backend adminservice stores them in dbo.ServiceStatus. Best-effort: a failed publish is
 * logged once per outage and never retried in a loop.
 */
class ServiceStatusReporter {
public:
    explicit ServiceStatusReporter(Config cfg);
    ~ServiceStatusReporter();

    ServiceStatusReporter(const ServiceStatusReporter&) = delete;
    ServiceStatusReporter& operator=(const ServiceStatusReporter&) = delete;

    void start();
    void stop();

private:
    void run();
    void publish(const std::string& event);

    Config cfg_;
    std::string machine_;
    bool warned_ = false;
    std::atomic<bool> stop_{false};
    std::mutex mu_;
    std::condition_variable cv_;
    std::thread worker_;
};

}  // namespace cproxy
