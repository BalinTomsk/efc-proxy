// Unit tests for the two pieces behind the public app surface (0.28.0): ResponseCache and the
// bounded RateLimiter. Framework-free like the others; time is passed in, so nothing here sleeps.
#include "check.hpp"
#include <chrono>
#include <iostream>
#include <string>

#include "rate_limiter.hpp"
#include "response_cache.hpp"

using namespace cproxy;
using namespace std::chrono_literals;

namespace {

CachedResponse answer(const std::string& body) {
    CachedResponse r;
    r.status = 200;
    r.content_type = "application/json";
    r.headers.emplace_back("ETag", "\"1\"");
    r.body = body;
    return r;
}

void a_stored_answer_is_returned_until_it_expires() {
    ResponseCache cache(60, 1024 * 1024, 1024 * 1024);
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(cache.find("k", t0) == nullptr);
    cache.store("k", answer("hello"), t0);
    const auto hit = cache.find("k", t0 + 59s);
    CHECK(hit != nullptr);
    CHECK(hit->body == "hello");
    CHECK(hit->content_type == "application/json");
    CHECK(hit->headers.size() == 1);
    // At the ttl it is gone, and it is dropped rather than left to be found again.
    CHECK(cache.find("k", t0 + 60s) == nullptr);
    CHECK(cache.entries() == 0);
    CHECK(cache.bytes() == 0);
}

void storing_again_replaces_the_entry_and_restarts_its_clock() {
    ResponseCache cache(60, 1024 * 1024, 1024 * 1024);
    const auto t0 = std::chrono::steady_clock::now();
    cache.store("k", answer("old"), t0);
    cache.store("k", answer("new"), t0 + 50s);
    CHECK(cache.entries() == 1);
    const auto hit = cache.find("k", t0 + 100s);
    CHECK(hit != nullptr && hit->body == "new");
}

void the_byte_budget_evicts_the_least_recently_used() {
    // Each entry costs a little over 100 bytes; the budget holds two of them, not three.
    ResponseCache cache(60, 300, 300);
    const auto t0 = std::chrono::steady_clock::now();
    const std::string body(100, 'x');
    cache.store("a", answer(body), t0);
    cache.store("b", answer(body), t0);
    CHECK(cache.find("a", t0) != nullptr);  // touch a: b is now the oldest
    cache.store("c", answer(body), t0);
    CHECK(cache.find("b", t0) == nullptr);
    CHECK(cache.find("a", t0) != nullptr);
    CHECK(cache.find("c", t0) != nullptr);
    CHECK(cache.bytes() <= 300);
}

void an_answer_over_the_entry_limit_is_not_kept() {
    ResponseCache cache(60, 10'000, 200);
    const auto t0 = std::chrono::steady_clock::now();
    cache.store("big", answer(std::string(500, 'x')), t0);
    CHECK(cache.find("big", t0) == nullptr);
    CHECK(cache.entries() == 0);
    // And it did not push anything else out on the way.
    cache.store("small", answer("ok"), t0);
    cache.store("big", answer(std::string(500, 'x')), t0);
    CHECK(cache.find("small", t0) != nullptr);
}

void a_hit_outlives_a_later_eviction() {
    // The caller holds the answer while writing it out; an eviction meanwhile must not free it.
    ResponseCache cache(60, 300, 300);
    const auto t0 = std::chrono::steady_clock::now();
    cache.store("a", answer(std::string(100, 'a')), t0);
    const auto held = cache.find("a", t0);
    cache.store("b", answer(std::string(100, 'b')), t0);
    cache.store("c", answer(std::string(100, 'c')), t0);
    CHECK(cache.find("a", t0) == nullptr);
    CHECK(held != nullptr && held->body == std::string(100, 'a'));
}

void an_unbounded_limiter_behaves_as_before() {
    RateLimiter limiter(60, 2);
    const auto t0 = std::chrono::steady_clock::now();
    int retry = 0;
    CHECK(limiter.allow("k", t0, retry));
    CHECK(limiter.allow("k", t0, retry));
    CHECK(!limiter.allow("k", t0, retry));
    CHECK(retry == 1);
    CHECK(limiter.allow("k", t0 + 1s, retry));  // 60/min = one token a second
    CHECK(limiter.allow("other", t0, retry));   // each key has its own bucket
}

void a_bounded_limiter_cannot_be_grown_by_inventing_keys() {
    RateLimiter limiter(60, 2, 3);
    const auto t0 = std::chrono::steady_clock::now();
    int retry = 0;
    CHECK(limiter.allow("a", t0, retry));
    CHECK(limiter.allow("b", t0, retry));
    CHECK(limiter.allow("c", t0, retry));
    CHECK(limiter.size() == 3);
    // Full, and every bucket is still mid-budget: the newcomer is refused, nobody is forgotten.
    CHECK(!limiter.allow("d", t0, retry));
    CHECK(retry == 1);
    CHECK(limiter.size() == 3);
    // A caller already tracked is unaffected by the table being full.
    CHECK(limiter.allow("a", t0, retry));
    CHECK(!limiter.allow("a", t0, retry));
}

void refilled_buckets_make_room_for_new_keys() {
    RateLimiter limiter(60, 2, 3);
    const auto t0 = std::chrono::steady_clock::now();
    int retry = 0;
    CHECK(limiter.allow("a", t0, retry));
    CHECK(limiter.allow("b", t0, retry));
    CHECK(limiter.allow("c", t0, retry));
    CHECK(limiter.allow("c", t0 + 5s, retry));  // c keeps spending; a and b go quiet
    CHECK(limiter.allow("c", t0 + 5s, retry));
    // By now a and b are full again, which is the same as never having been seen: they are dropped.
    CHECK(limiter.allow("d", t0 + 5s, retry));
    CHECK(limiter.size() == 2);  // c and d
    // c was NOT dropped, so its spent budget still counts.
    CHECK(!limiter.allow("c", t0 + 5s, retry));
}

}  // namespace

int main() {
    a_stored_answer_is_returned_until_it_expires();
    storing_again_replaces_the_entry_and_restarts_its_clock();
    the_byte_budget_evicts_the_least_recently_used();
    an_answer_over_the_entry_limit_is_not_kept();
    a_hit_outlives_a_later_eviction();
    an_unbounded_limiter_behaves_as_before();
    a_bounded_limiter_cannot_be_grown_by_inventing_keys();
    refilled_buckets_make_room_for_new_keys();
    std::cout << "response_cache_test: all assertions passed\n";
    return 0;
}
