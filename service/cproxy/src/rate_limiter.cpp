#include "rate_limiter.hpp"

#include <algorithm>
#include <cmath>

namespace cproxy {

RateLimiter::RateLimiter(int per_minute, int burst, std::size_t max_keys)
    : per_second_(std::max(1, per_minute) / 60.0), burst_(std::max(1, burst)), max_keys_(max_keys) {}

bool RateLimiter::allow(const std::string& key, std::chrono::steady_clock::time_point now,
                        int& retry_after_seconds) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        if (max_keys_ != 0 && buckets_.size() >= max_keys_) {
            drop_refilled(now);
            if (buckets_.size() >= max_keys_) {
                // Every tracked caller is still mid-budget: refuse the newcomer rather than forget one.
                retry_after_seconds = 1;
                return false;
            }
        }
        it = buckets_.emplace(key, Bucket{burst_, now}).first;
    } else {
        Bucket& b = it->second;
        const double elapsed = std::chrono::duration<double>(now - b.updated).count();
        if (elapsed > 0) b.tokens = std::min(burst_, b.tokens + elapsed * per_second_);
        b.updated = now;
    }
    Bucket& b = it->second;
    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        return true;
    }
    retry_after_seconds = std::max(1, static_cast<int>(std::ceil((1.0 - b.tokens) / per_second_)));
    return false;
}

std::size_t RateLimiter::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return buckets_.size();
}

void RateLimiter::drop_refilled(std::chrono::steady_clock::time_point now) {
    std::erase_if(buckets_, [&](const auto& entry) {
        const Bucket& b = entry.second;
        const double elapsed = std::chrono::duration<double>(now - b.updated).count();
        return b.tokens + std::max(0.0, elapsed) * per_second_ >= burst_;
    });
}

}  // namespace cproxy
