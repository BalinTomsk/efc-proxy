#pragma once

#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

namespace cproxy {

/**
 * Token bucket per caller key (0.20.0, for the MCP path). Each key starts with `burst` tokens and
 * regains `per_minute` of them per minute, never holding more than `burst`; a request costs one.
 *
 * Exists because an MCP client is a model in a loop: it can fire tool calls far faster than a person
 * clicks, and every one lands on docapi, whose single shared SQL circuit breaker opens for the WHOLE
 * API after a handful of failures. The limit keeps one runaway client from becoming a site outage.
 *
 * Keyed by the MCP key id, never by IP: the key is the identity, and the set of ids is bounded by the
 * key store, so the map cannot be grown by a caller.
 */
class RateLimiter {
public:
    RateLimiter(int per_minute, int burst);

    /**
     * Spends one token for `key`. False when the bucket is empty; `retry_after_seconds` is then set to
     * the whole seconds until a token is back (at least 1).
     */
    bool allow(const std::string& key, std::chrono::steady_clock::time_point now,
               int& retry_after_seconds);

private:
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point updated;
    };

    double per_second_;
    double burst_;
    std::mutex mu_;
    std::unordered_map<std::string, Bucket> buckets_;
};

}  // namespace cproxy
