#include "rate_limiter.hpp"

#include <algorithm>
#include <cmath>

namespace cproxy {

RateLimiter::RateLimiter(int per_minute, int burst)
    : per_second_(std::max(1, per_minute) / 60.0), burst_(std::max(1, burst)) {}

bool RateLimiter::allow(const std::string& key, std::chrono::steady_clock::time_point now,
                        int& retry_after_seconds) {
    std::lock_guard<std::mutex> lock(mu_);
    auto [it, inserted] = buckets_.try_emplace(key, Bucket{burst_, now});
    Bucket& b = it->second;
    if (!inserted) {
        const double elapsed = std::chrono::duration<double>(now - b.updated).count();
        if (elapsed > 0) b.tokens = std::min(burst_, b.tokens + elapsed * per_second_);
        b.updated = now;
    }
    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        return true;
    }
    retry_after_seconds = std::max(1, static_cast<int>(std::ceil((1.0 - b.tokens) / per_second_)));
    return false;
}

}  // namespace cproxy
