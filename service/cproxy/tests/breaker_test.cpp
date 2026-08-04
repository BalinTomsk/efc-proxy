// Unit tests for the circuit-breaker state machine. Time is passed in, so the cooldown is tested
// without sleeping. Framework-free; registered with CTest.
#include "check.hpp"

#include <chrono>
#include <iostream>

#include "breaker.hpp"

using namespace cproxy;
using namespace std::chrono_literals;

namespace {

using TP = CircuitBreaker::TimePoint;
const TP t0{};  // an arbitrary epoch; only differences matter

TP at(std::chrono::milliseconds ms) { return t0 + ms; }

void closed_until_threshold_then_opens() {
    CircuitBreaker b(3, 1000ms);
    CHECK(b.state(t0) == CircuitBreaker::State::Closed);
    CHECK(b.allow(t0));

    b.on_failure(at(10ms));
    b.on_failure(at(20ms));
    CHECK(b.state(at(20ms)) == CircuitBreaker::State::Closed);  // below threshold
    CHECK(b.allow(at(20ms)));

    b.on_failure(at(30ms));  // third consecutive -> open
    CHECK(b.state(at(30ms)) == CircuitBreaker::State::Open);
    CHECK(!b.allow(at(30ms)));  // fails fast now
}

void open_fails_fast_until_cooldown_then_one_probe() {
    CircuitBreaker b(1, 1000ms);
    b.on_failure(t0);
    CHECK(!b.allow(at(999ms)));  // still inside the cooldown

    // Cooldown elapsed: exactly ONE probe is admitted, further callers keep failing fast.
    CHECK(b.state(at(1000ms)) == CircuitBreaker::State::HalfOpen);
    CHECK(b.allow(at(1000ms)));
    CHECK(!b.allow(at(1001ms)));
    CHECK(!b.allow(at(1002ms)));
}

void half_open_success_closes_and_resets() {
    CircuitBreaker b(2, 1000ms);
    b.on_failure(t0);
    b.on_failure(at(1ms));
    CHECK(b.allow(at(1001ms)));  // probe
    b.on_success();

    CHECK(b.state(at(1002ms)) == CircuitBreaker::State::Closed);
    CHECK(b.allow(at(1002ms)));
    // The failure count reset too: a single new failure must not re-open a threshold-2 breaker.
    b.on_failure(at(1003ms));
    CHECK(b.state(at(1003ms)) == CircuitBreaker::State::Closed);
}

void half_open_failure_reopens_with_fresh_cooldown() {
    CircuitBreaker b(1, 1000ms);
    b.on_failure(t0);
    CHECK(b.allow(at(1000ms)));  // probe
    b.on_failure(at(1000ms));    // probe failed -> open again, cooldown restarts here

    CHECK(!b.allow(at(1500ms)));                                    // inside the NEW cooldown
    CHECK(b.state(at(1500ms)) == CircuitBreaker::State::Open);
    CHECK(b.allow(at(2000ms)));                                     // next probe after full cooldown
}

void success_resets_the_consecutive_counter() {
    CircuitBreaker b(3, 1000ms);
    b.on_failure(at(1ms));
    b.on_failure(at(2ms));
    b.on_success();          // streak broken
    b.on_failure(at(3ms));
    b.on_failure(at(4ms));   // only 2 consecutive -> still closed
    CHECK(b.state(at(4ms)) == CircuitBreaker::State::Closed);
    CHECK(b.allow(at(4ms)));
}

void threshold_zero_disables_the_breaker() {
    CircuitBreaker b(0, 1000ms);
    CHECK(!b.enabled());
    for (int i = 0; i < 50; ++i) b.on_failure(at(std::chrono::milliseconds(i)));
    CHECK(b.allow(at(100ms)));  // never opens
    CHECK(b.state(at(100ms)) == CircuitBreaker::State::Closed);
}

}  // namespace

int main() {
    closed_until_threshold_then_opens();
    open_fails_fast_until_cooldown_then_one_probe();
    half_open_success_closes_and_resets();
    half_open_failure_reopens_with_fresh_cooldown();
    success_resets_the_consecutive_counter();
    threshold_zero_disables_the_breaker();
    std::cout << "breaker_test: all assertions passed\n";
    return 0;
}
