// Framework-free unit tests for ClockOffset — the in-process correction an admin request may apply
// to cproxy's notion of "now" for credential validation. Registered with CTest.
//
// The bound is the point of most of these: the offset is the one thing in the gate that a REQUEST
// can move, so "how far can a caller push it" is the property worth pinning, not the arithmetic.
#include "check.hpp"

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "clock_offset.hpp"

using namespace cproxy;

namespace {

void a_fresh_offset_is_zero_and_reads_the_host_clock() {
    ClockOffset clock;
    CHECK(clock.offset_seconds() == 0);

    const auto host = std::chrono::system_clock::now();
    const auto seen = clock.now();
    // Same clock, so the only gap is however long the two calls took.
    CHECK(std::chrono::abs(seen - host) < std::chrono::seconds(2));
}

void adopting_a_delta_moves_now_by_that_much() {
    ClockOffset clock;
    CHECK(clock.adopt(45, 3600));
    CHECK(clock.offset_seconds() == 45);

    const auto ahead = clock.now() - std::chrono::system_clock::now();
    CHECK(ahead > std::chrono::seconds(43) && ahead < std::chrono::seconds(47));
}

void a_negative_delta_moves_the_clock_backwards() {
    ClockOffset clock;
    CHECK(clock.adopt(-120, 3600));
    CHECK(clock.offset_seconds() == -120);
    CHECK(clock.now() < std::chrono::system_clock::now());
}

void deltas_accumulate_rather_than_replace() {
    ClockOffset clock;
    CHECK(clock.adopt(10, 3600));
    CHECK(clock.adopt(5, 3600));
    // The caller passes the gap it still sees, not an absolute reading, so corrections compose.
    CHECK(clock.offset_seconds() == 15);
}

void the_total_offset_is_clamped_to_the_ceiling() {
    ClockOffset clock;
    CHECK(clock.adopt(86400, 3600));
    CHECK(clock.offset_seconds() == 3600);

    CHECK(clock.adopt(-86400, 3600));
    CHECK(clock.offset_seconds() == -3600);
}

void the_ceiling_cannot_be_walked_past_in_small_steps() {
    // THE security property. Clamping each STEP would let a caller reach any offset it liked by
    // repeating a request, so the clamp is on the running TOTAL. Ten adopts of 100s against a 500s
    // ceiling must land on 500, not 1000.
    ClockOffset clock;
    for (int i = 0; i < 10; ++i) {
        clock.adopt(100, 500);
    }
    CHECK(clock.offset_seconds() == 500);
}

void an_adopt_that_changes_nothing_reports_false() {
    ClockOffset clock;
    CHECK(clock.adopt(3600, 3600));
    // Already pinned at the ceiling: pushing further is refused, and the caller is told so it can
    // log "refused" instead of reporting a correction that did not happen.
    CHECK(!clock.adopt(60, 3600));
    CHECK(clock.offset_seconds() == 3600);
    // A zero delta is likewise not a change.
    CHECK(!clock.adopt(0, 3600));
}

void a_zero_ceiling_pins_the_host_clock() {
    // CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS=0 is the "never move" setting, reachable without also
    // turning the feature off.
    ClockOffset clock;
    CHECK(!clock.adopt(900, 0));
    CHECK(clock.offset_seconds() == 0);
}

void concurrent_adopts_do_not_stack_past_the_ceiling() {
    // Two admin requests landing together must not each add their delta to the same starting value
    // and end at twice the correction — the reason adopt() is a compare_exchange loop and not a
    // fetch_add. Threads all push in the same direction against a ceiling they would blow past if
    // the update were not atomic.
    ClockOffset clock;
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&clock] {
            for (int n = 0; n < 200; ++n) clock.adopt(50, 600);
        });
    }
    for (std::thread& t : threads) t.join();
    CHECK(clock.offset_seconds() == 600);
}

}  // namespace

int main() {
    a_fresh_offset_is_zero_and_reads_the_host_clock();
    adopting_a_delta_moves_now_by_that_much();
    a_negative_delta_moves_the_clock_backwards();
    deltas_accumulate_rather_than_replace();
    the_total_offset_is_clamped_to_the_ceiling();
    the_ceiling_cannot_be_walked_past_in_small_steps();
    an_adopt_that_changes_nothing_reports_false();
    a_zero_ceiling_pins_the_host_clock();
    concurrent_adopts_do_not_stack_past_the_ceiling();

    std::cout << "clock_offset_test: all checks passed\n";
    return 0;
}
