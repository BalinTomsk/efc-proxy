#pragma once

#include <chrono>
#include <cstddef>
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
 * The MCP path keys it by the MCP key id, never by IP: the key is the identity, and the set of ids is
 * bounded by the key store, so that map cannot be grown by a caller.
 *
 * The public app surface (0.28.0) has no identity but the peer address, and addresses ARE chosen by
 * the caller, so that limiter is built with `max_keys`. At the bound, buckets that have refilled
 * completely are dropped first (a full bucket is indistinguishable from an absent one); if every
 * bucket is still in use the NEW key is refused, so a flood of addresses cannot grow the map or
 * push out the buckets that are holding real callers back.
 */
class RateLimiter {
public:
    /** `max_keys` 0 = unbounded (only safe when the caller cannot invent keys). */
    RateLimiter(int per_minute, int burst, std::size_t max_keys = 0);

    /**
     * Spends one token for `key`. False when the bucket is empty; `retry_after_seconds` is then set to
     * the whole seconds until a token is back (at least 1).
     */
    bool allow(const std::string& key, std::chrono::steady_clock::time_point now,
               int& retry_after_seconds);

    /** Keys currently tracked. */
    std::size_t size() const;

private:
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point updated;
    };

    /** Drops every bucket that would be full again by `now`. Caller holds the mutex. */
    void drop_refilled(std::chrono::steady_clock::time_point now);

    double per_second_;
    double burst_;
    std::size_t max_keys_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, Bucket> buckets_;
};

}  // namespace cproxy
