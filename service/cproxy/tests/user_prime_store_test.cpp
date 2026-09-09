// Framework-free unit tests for UserPrimeStore — the half of the JWT gate that decides whether the
// token's `user` claim belongs to a live account. Registered with CTest.
//
// The fixtures build a throwaway mirror with the same schema AccountMirrorStore creates, so a
// divergence between the two shapes fails here rather than in production.
#include "check.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "user_prime_store.hpp"

using namespace cproxy;

namespace {

struct Account {
    std::string id;
    long long user_prime;
    long long day_prime;
    int day_year;
    int suspended = 0;
    int deleted = 0;
    const char* prime_expired = nullptr;  // nullptr => NULL
};

void exec(sqlite3* db, const std::string& sql) {
    CHECK(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

std::string quoted_or_null(const char* value) {
    return value == nullptr ? std::string("NULL") : "'" + std::string(value) + "'";
}

/** Mirror file with the users_sync / user_prime_sync shape AccountMirrorStore::ensure_schema makes. */
void write_mirror(const std::string& path, const std::vector<Account>& accounts) {
    std::remove(path.c_str());
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    exec(db,
         "CREATE TABLE users_sync (id TEXT PRIMARY KEY, users_id INTEGER NOT NULL DEFAULT 0,"
         " user_name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '',"
         " last_visit TEXT NOT NULL DEFAULT '', access INTEGER NOT NULL DEFAULT 0,"
         " suspended INTEGER NOT NULL DEFAULT 0, auth_type TEXT NOT NULL DEFAULT '',"
         " deleted INTEGER NOT NULL DEFAULT 0, deleted_utc TEXT NULL,"
         " prime INTEGER NOT NULL DEFAULT 0, prime_expired TEXT NULL,"
         " updated_utc TEXT NOT NULL)");
    exec(db,
         "CREATE TABLE user_prime_sync (user_id TEXT NOT NULL, day_year INTEGER NOT NULL,"
         " prime INTEGER NOT NULL DEFAULT 0, updated_utc TEXT NOT NULL,"
         " PRIMARY KEY (user_id, day_year))");
    for (const Account& a : accounts) {
        exec(db, "INSERT INTO users_sync (id, prime, suspended, deleted, prime_expired, updated_utc)"
                 " VALUES ('" + a.id + "', " + std::to_string(a.user_prime) + ", " +
                     std::to_string(a.suspended) + ", " + std::to_string(a.deleted) + ", " +
                     quoted_or_null(a.prime_expired) + ", '2026-09-08T00:00:00Z')");
        exec(db, "INSERT INTO user_prime_sync (user_id, day_year, prime, updated_utc) VALUES ('" +
                     a.id + "', " + std::to_string(a.day_year) + ", " +
                     std::to_string(a.day_prime) + ", '2026-09-08T00:00:00Z')");
    }
    sqlite3_close(db);
}

std::chrono::system_clock::time_point at(int y, unsigned m, unsigned d) {
    return std::chrono::sys_days{std::chrono::year{y} / std::chrono::month{m} / std::chrono::day{d}};
}

// 2026-09-08 is day 251 of the year; the tests key their fixtures off that.
const int kSep8 = 251;

void the_product_of_the_two_primes_identifies_the_account() {
    const std::string path = "user_prime_store_test_1.sqlite";
    write_mirror(path, {{"user-a", 1000003, 104729, kSep8}});
    UserPrimeStore store(path, 60);

    const auto now = at(2026, 9, 8);
    CHECK(UserPrimeStore::day_of_year(now) == kSep8);
    CHECK(store.is_valid("104729314187", now));  // 1000003 * 104729
    CHECK(!store.is_valid("104729314088", now));
    CHECK(!store.is_valid("1000003", now));  // a factor on its own proves nothing
    CHECK(!store.is_valid("", now));
    CHECK(store.last_error().empty());
    std::remove(path.c_str());
}

void a_product_past_2_to_the_63_still_matches() {
    // Two bigint primes near the top of the range multiply well past int64. Computing this in 64-bit
    // would wrap to a different number that either fails to match a legitimate caller or, worse,
    // matches something else. The store multiplies in 128 bits and compares decimal text.
    const std::string path = "user_prime_store_test_2.sqlite";
    write_mirror(path, {{"user-big", 4000000007LL, 4000000009LL, kSep8}});
    UserPrimeStore store(path, 60);

    CHECK(store.is_valid("16000000064000000063", at(2026, 9, 8)));
    std::remove(path.c_str());
}

void suspended_deleted_unallocated_and_expired_accounts_do_not_match() {
    const std::string path = "user_prime_store_test_3.sqlite";
    write_mirror(path, {{"suspended", 1000003, 104729, kSep8, /*suspended=*/1},
                        {"deleted", 1000033, 104743, kSep8, 0, /*deleted=*/1},
                        // prime = 0 is the normal state between the 'created' and 'updated' events
                        // for a fresh account, not a parse failure — it simply matches nothing.
                        {"unallocated", 0, 104759, kSep8},
                        {"expired", 1000037, 104761, kSep8, 0, 0, "2026-01-01"},
                        {"live", 1000039, 104773, kSep8, 0, 0, "2027-01-01"}});
    UserPrimeStore store(path, 60);

    const auto now = at(2026, 9, 8);
    CHECK(!store.is_valid("104729314187", now));   // suspended
    CHECK(!store.is_valid("104746456519", now));   // deleted:  1000033 * 104743
    CHECK(!store.is_valid("0", now));              // unallocated
    CHECK(!store.is_valid("104764876157", now));   // expired:  1000037 * 104761
    CHECK(store.is_valid("104777086147", now));    // live:     1000039 * 104773
    std::remove(path.c_str());
}

void the_day_window_spans_yesterday_today_and_tomorrow() {
    // Same reason DayKeyStore accepts three days: a request that crosses UTC midnight between the
    // frontend minting the token and cproxy checking it must not be spuriously refused.
    const std::string path = "user_prime_store_test_4.sqlite";
    write_mirror(path, {{"yesterday", 1000003, 104729, kSep8 - 1},
                        {"tomorrow", 1000033, 104743, kSep8 + 1},
                        {"far-off", 1000037, 104761, kSep8 + 5}});
    UserPrimeStore store(path, 60);

    const auto now = at(2026, 9, 8);
    CHECK(store.is_valid("104729314187", now));
    CHECK(store.is_valid("104746456519", now));
    CHECK(!store.is_valid("104764876157", now));  // five days out is not in the window
    std::remove(path.c_str());
}

void the_year_boundary_wraps_instead_of_asking_for_day_zero() {
    const std::string path = "user_prime_store_test_5.sqlite";
    write_mirror(path, {{"new-year-eve", 1000003, 104729, 365}, {"new-year-day", 1000033, 104743, 1}});
    UserPrimeStore store(path, 60);

    const auto jan1 = at(2027, 1, 1);
    CHECK(UserPrimeStore::day_of_year(jan1) == 1);
    CHECK(store.is_valid("104746456519", jan1));  // today
    CHECK(store.is_valid("104729314187", jan1));  // yesterday == day 365, not day 0
    std::remove(path.c_str());
}

void the_leap_day_overflow_clamps_to_day_365() {
    // dbo.Users_Prime holds exactly 365 rows per account (CHECK day_year 1..365), so 31 December of
    // a leap year has no prime of its own and reuses day 365 — the same clamp on both sides.
    CHECK(UserPrimeStore::day_of_year(at(2028, 12, 31)) == 365);
    CHECK(UserPrimeStore::day_of_year(at(2028, 12, 30)) == 365);
    CHECK(UserPrimeStore::day_of_year(at(2028, 12, 29)) == 364);
}

void a_missing_mirror_matches_nothing_and_says_why() {
    // Fail CLOSED, unlike the cloud-range store: this is only consulted when an operator has turned
    // CPROXY_JWT_REQUIRE_USER on, which is them asserting the mirror is live.
    UserPrimeStore store("user_prime_store_test_does_not_exist.sqlite", 60);
    CHECK(!store.is_valid("104729314187", at(2026, 9, 8)));
    CHECK(store.size() == 0);
    CHECK(!store.last_error().empty());
}

void a_non_numeric_claim_is_refused_without_touching_the_snapshot() {
    const std::string path = "user_prime_store_test_6.sqlite";
    write_mirror(path, {{"user-a", 1000003, 104729, kSep8}});
    UserPrimeStore store(path, 60);

    const auto now = at(2026, 9, 8);
    CHECK(!store.is_valid("104729314187 OR 1=1", now));
    CHECK(!store.is_valid("-104729314187", now));
    CHECK(!store.is_valid("1.04729e11", now));
    std::remove(path.c_str());
}

void a_revoked_account_disappears_once_the_snapshot_ttl_expires() {
    const std::string path = "user_prime_store_test_7.sqlite";
    write_mirror(path, {{"user-a", 1000003, 104729, kSep8}});
    UserPrimeStore store(path, 60);

    const auto now = at(2026, 9, 8);
    CHECK(store.is_valid("104729314187", now));

    write_mirror(path, {{"user-a", 1000003, 104729, kSep8, /*suspended=*/1}});
    CHECK(store.is_valid("104729314187", now));                              // still cached
    CHECK(!store.is_valid("104729314187", now + std::chrono::seconds{61}));  // past the TTL
    std::remove(path.c_str());
}

}  // namespace

int main() {
    the_product_of_the_two_primes_identifies_the_account();
    a_product_past_2_to_the_63_still_matches();
    suspended_deleted_unallocated_and_expired_accounts_do_not_match();
    the_day_window_spans_yesterday_today_and_tomorrow();
    the_year_boundary_wraps_instead_of_asking_for_day_zero();
    the_leap_day_overflow_clamps_to_day_365();
    a_missing_mirror_matches_nothing_and_says_why();
    a_non_numeric_claim_is_refused_without_touching_the_snapshot();
    a_revoked_account_disappears_once_the_snapshot_ttl_expires();
    std::cout << "user_prime_store_test: all checks passed\n";
    return 0;
}
