#pragma once

#include <chrono>
#include <cstddef>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace cproxy {

/** One upstream answer, kept exactly as it will be replayed. */
struct CachedResponse {
    int status = 200;
    std::string content_type;
    std::vector<std::pair<std::string, std::string>> headers;  // already filtered for forwarding
    std::string body;
};

/**
 * A small in-memory cache of upstream answers for the public app surface (0.28.0).
 *
 * Exists because the upstreams are small (one shared vCPU runs three services) and docapi's single
 * SQL circuit breaker opens for the WHOLE API after a handful of failures: a few hundred phones
 * opening the same news list must cost one upstream call per `ttl`, not one each.
 *
 * Bounded on purpose, twice: by total body bytes (least-recently-used entries go first) and per
 * entry (a large answer is simply not kept). An entry older than the ttl is never returned. Nothing
 * here decides WHAT may be cached -- the caller does, and only ever stores an anonymous 200.
 */
class ResponseCache {
public:
    ResponseCache(int ttl_seconds, std::size_t max_bytes, std::size_t max_entry_bytes);

    /** The live entry for `key`, or null. A hit moves the entry to the front of the eviction order. */
    std::shared_ptr<const CachedResponse> find(const std::string& key,
                                               std::chrono::steady_clock::time_point now);

    /** Keeps `value` under `key`, replacing any older entry. Ignored when it is over the entry limit. */
    void store(const std::string& key, CachedResponse value,
               std::chrono::steady_clock::time_point now);

    std::size_t entries() const;
    std::size_t bytes() const;

private:
    struct Entry {
        std::string key;
        std::shared_ptr<const CachedResponse> value;
        std::size_t size;
        std::chrono::steady_clock::time_point stored;
    };

    void erase(std::list<Entry>::iterator it);

    std::chrono::seconds ttl_;
    std::size_t max_bytes_;
    std::size_t max_entry_bytes_;
    mutable std::mutex mu_;
    std::list<Entry> order_;  // front = most recently used
    std::unordered_map<std::string, std::list<Entry>::iterator> index_;
    std::size_t bytes_ = 0;
};

}  // namespace cproxy
