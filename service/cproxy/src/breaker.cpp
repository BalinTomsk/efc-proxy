#include "breaker.hpp"

namespace cproxy {

CircuitBreaker::CircuitBreaker(int failure_threshold, std::chrono::milliseconds cooldown)
    : threshold_(failure_threshold), cooldown_(cooldown) {}

bool CircuitBreaker::allow(TimePoint now) {
    if (!enabled()) return true;
    std::lock_guard<std::mutex> lock(mu_);
    if (!open_) return true;
    if (now - opened_at_ < cooldown_) return false;  // still failing fast
    if (probe_in_flight_) return false;              // half-open: exactly one probe at a time
    probe_in_flight_ = true;
    return true;
}

void CircuitBreaker::on_success() {
    if (!enabled()) return;
    std::lock_guard<std::mutex> lock(mu_);
    consecutive_failures_ = 0;
    open_ = false;
    probe_in_flight_ = false;
}

void CircuitBreaker::on_failure(TimePoint now) {
    if (!enabled()) return;
    std::lock_guard<std::mutex> lock(mu_);
    if (probe_in_flight_) {
        // The half-open probe failed: straight back to open with a fresh cooldown.
        probe_in_flight_ = false;
        open_ = true;
        opened_at_ = now;
        return;
    }
    if (++consecutive_failures_ >= threshold_) {
        open_ = true;
        opened_at_ = now;
    }
}

CircuitBreaker::State CircuitBreaker::state(TimePoint now) const {
    if (!enabled()) return State::Closed;
    std::lock_guard<std::mutex> lock(mu_);
    if (!open_) return State::Closed;
    // Past the cooldown the breaker is willing to probe, which is what "half open" reports.
    if (!probe_in_flight_ && now - opened_at_ >= cooldown_) return State::HalfOpen;
    return State::Open;
}

const char* to_string(CircuitBreaker::State s) {
    switch (s) {
        case CircuitBreaker::State::Open: return "open";
        case CircuitBreaker::State::HalfOpen: return "half_open";
        default: return "closed";
    }
}

}  // namespace cproxy
