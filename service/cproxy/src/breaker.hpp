#pragma once

#include <chrono>
#include <mutex>

namespace cproxy {

/**
 * Consecutive-failure circuit breaker guarding the upstream call.
 *
 * Without it, every request during an upstream outage burns the full connect timeout and occupies a
 * worker thread, so one dead upstream drags the whole proxy down. After `failure_threshold`
 * consecutive transport failures the breaker OPENS and requests fail fast with 502; once `cooldown`
 * has elapsed it lets exactly ONE probe through (HALF-OPEN) — success closes it, failure re-opens it
 * with a fresh cooldown. HTTP error statuses from a reachable upstream are NOT failures; only
 * transport-level errors (unreachable, timeout) are.
 *
 * The clock is a parameter rather than read internally so the state machine is unit-testable without
 * sleeping. All methods are thread-safe.
 */
class CircuitBreaker {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    enum class State { Closed = 0, Open = 1, HalfOpen = 2 };

    /** `failure_threshold <= 0` disables the breaker entirely (always allow, always Closed). */
    CircuitBreaker(int failure_threshold, std::chrono::milliseconds cooldown);

    /** True when the caller may attempt the upstream. Consumes the half-open probe slot. */
    bool allow(TimePoint now);

    /** Report a completed upstream exchange (any HTTP status counts as reachable). */
    void on_success();

    /** Report a transport-level failure (unreachable/timeout). */
    void on_failure(TimePoint now);

    /** Current state for reporting; an Open breaker past its cooldown reports HalfOpen. */
    State state(TimePoint now) const;

    bool enabled() const { return threshold_ > 0; }

private:
    mutable std::mutex mu_;
    int threshold_;
    std::chrono::milliseconds cooldown_;
    int consecutive_failures_ = 0;
    bool open_ = false;
    bool probe_in_flight_ = false;
    TimePoint opened_at_{};
};

/** "closed" / "open" / "half_open" — used in /health/ready and /metrics output. */
const char* to_string(CircuitBreaker::State s);

}  // namespace cproxy
