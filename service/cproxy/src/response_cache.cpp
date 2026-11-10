#include "response_cache.hpp"

#include <algorithm>

namespace cproxy {

namespace {

/** What an entry costs against the byte budget: the body plus everything stored beside it. */
std::size_t cost_of(const std::string& key, const CachedResponse& r) {
    std::size_t n = key.size() + r.body.size() + r.content_type.size();
    for (const auto& [k, v] : r.headers) n += k.size() + v.size();
    return n;
}

}  // namespace

ResponseCache::ResponseCache(int ttl_seconds, std::size_t max_bytes, std::size_t max_entry_bytes)
    : ttl_(std::max(1, ttl_seconds)),
      max_bytes_(max_bytes),
      max_entry_bytes_(std::min(max_entry_bytes, max_bytes)) {}

std::shared_ptr<const CachedResponse> ResponseCache::find(const std::string& key,
                                                          std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto found = index_.find(key);
    if (found == index_.end()) return nullptr;
    const auto it = found->second;
    if (now - it->stored >= ttl_) {
        erase(it);
        return nullptr;
    }
    order_.splice(order_.begin(), order_, it);
    return it->value;
}

void ResponseCache::store(const std::string& key, CachedResponse value,
                          std::chrono::steady_clock::time_point now) {
    const std::size_t size = cost_of(key, value);
    if (size > max_entry_bytes_) return;
    std::lock_guard<std::mutex> lock(mu_);
    if (const auto found = index_.find(key); found != index_.end()) erase(found->second);
    while (!order_.empty() && bytes_ + size > max_bytes_) erase(std::prev(order_.end()));
    order_.push_front(Entry{key, std::make_shared<const CachedResponse>(std::move(value)), size, now});
    index_[key] = order_.begin();
    bytes_ += size;
}

std::size_t ResponseCache::entries() const {
    std::lock_guard<std::mutex> lock(mu_);
    return order_.size();
}

std::size_t ResponseCache::bytes() const {
    std::lock_guard<std::mutex> lock(mu_);
    return bytes_;
}

void ResponseCache::erase(std::list<Entry>::iterator it) {
    bytes_ -= it->size;
    index_.erase(it->key);
    order_.erase(it);
}

}  // namespace cproxy
