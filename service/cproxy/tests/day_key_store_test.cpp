// Minimal, framework-free unit tests for the day-key store (SQLite-backed rotating credential).
// Registered with CTest; run via `ctest --test-dir build` (also executed inside the Docker build).
//
// The store is date-keyed as of 0.9.0 — see day_key_store.hpp for why. These tests use fixed dates
// and pass an explicit `now`, so they never depend on the wall clock.
#include "check.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "day_key_store.hpp"

using namespace cproxy;

namespace {

/** Builds a throwaway SQLite file with the date-keyed schema and the given (stamp, guid) rows. */
void write_test_db(const std::string& path,
                   const std::vector<std::pair<std::string, std::string>>& rows) {
    std::remove(path.c_str());
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE day_keys (stamp TEXT PRIMARY KEY, guid TEXT NOT NULL)",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "INSERT INTO day_keys (stamp, guid) VALUES (?, ?)", -1, &stmt,
                             nullptr) == SQLITE_OK);
    for (const auto& [stamp, guid] : rows) {
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, stamp.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, guid.c_str(), -1, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(stmt) == SQLITE_DONE);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

/** A run of consecutive days starting at `start`, with guid "KEY-<stamp>". */
std::vector<std::pair<std::string, std::string>> consecutive_days(std::chrono::sys_days start,
                                                                 int count) {
    std::vector<std::pair<std::string, std::string>> rows;
    for (int i = 0; i < count; ++i) {
        const std::string stamp = utc_date_string(start + std::chrono::days{i});
        rows.emplace_back(stamp, "KEY-" + stamp);
    }
    return rows;
}

std::chrono::system_clock::time_point at(int y, unsigned m, unsigned d) {
    return std::chrono::sys_days{std::chrono::year{y} / std::chrono::month{m} / std::chrono::day{d}};
}

void today_matches_the_stored_key_for_that_date() {
    const std::string path = "day_key_store_test_1.sqlite";
    write_test_db(path, consecutive_days(std::chrono::sys_days{std::chrono::year{2026} /
                                                               std::chrono::September / 1}, 10));
    DayKeyStore store(path);

    const auto now = at(2026, 9, 5);
    CHECK(store.is_valid("KEY-2026-09-05", now));
    CHECK(store.is_valid("key-2026-09-05", now));   // case-insensitive
    CHECK(!store.is_valid("KEY-2026-09-08", now));  // outside the three-day window
    std::remove(path.c_str());
}

void yesterday_and_tomorrow_are_accepted() {
    const std::string path = "day_key_store_test_2.sqlite";
    write_test_db(path, consecutive_days(std::chrono::sys_days{std::chrono::year{2026} /
                                                               std::chrono::September / 1}, 10));
    DayKeyStore store(path);

    const auto now = at(2026, 9, 5);
    CHECK(store.is_valid("KEY-2026-09-04", now));   // yesterday
    CHECK(store.is_valid("KEY-2026-09-05", now));   // today
    CHECK(store.is_valid("KEY-2026-09-06", now));   // tomorrow
    CHECK(!store.is_valid("KEY-2026-09-03", now));  // two days back
    CHECK(!store.is_valid("KEY-2026-09-07", now));  // two days forward
    std::remove(path.c_str());
}

/**
 * The year boundary needs no special handling now — it is ordinary date arithmetic. Under the old
 * day-of-year scheme this required wrapping 365 -> 1 by hand.
 */
void year_boundary_needs_no_special_case() {
    const std::string path = "day_key_store_test_3.sqlite";
    write_test_db(path, consecutive_days(std::chrono::sys_days{std::chrono::year{2026} /
                                                               std::chrono::December / 29}, 6));
    DayKeyStore store(path);

    const auto new_year = at(2027, 1, 1);
    CHECK(store.is_valid("KEY-2026-12-31", new_year));  // yesterday, previous year
    CHECK(store.is_valid("KEY-2027-01-01", new_year));  // today
    CHECK(store.is_valid("KEY-2027-01-02", new_year));  // tomorrow

    const auto new_years_eve = at(2026, 12, 31);
    CHECK(store.is_valid("KEY-2026-12-30", new_years_eve));
    CHECK(store.is_valid("KEY-2027-01-01", new_years_eve));  // tomorrow, next year
    std::remove(path.c_str());
}

/**
 * 29 February is a real, distinct key now. The day-of-year scheme could not represent it at all —
 * day 366 was clamped onto day 365's key, so the leap day and 31 December shared a credential.
 */
void leap_day_has_its_own_key() {
    const std::string path = "day_key_store_test_4.sqlite";
    write_test_db(path, consecutive_days(std::chrono::sys_days{std::chrono::year{2028} /
                                                               std::chrono::February / 27}, 5));
    DayKeyStore store(path);

    const auto leap_day = at(2028, 2, 29);
    CHECK(store.is_valid("KEY-2028-02-29", leap_day));
    CHECK(store.is_valid("KEY-2028-02-28", leap_day));  // yesterday
    CHECK(store.is_valid("KEY-2028-03-01", leap_day));  // tomorrow
    // ...and it is NOT shared with any other date.
    CHECK(!store.is_valid("KEY-2028-02-29", at(2028, 3, 2)));
    std::remove(path.c_str());
}

void unknown_empty_and_uncovered_dates_are_rejected() {
    const std::string path = "day_key_store_test_5.sqlite";
    write_test_db(path, consecutive_days(std::chrono::sys_days{std::chrono::year{2026} /
                                                               std::chrono::September / 1}, 10));
    DayKeyStore store(path);

    const auto now = at(2026, 9, 5);
    CHECK(!store.is_valid("", now));
    CHECK(!store.is_valid("not-a-real-key", now));

    // A date outside the store's range matches nothing — fail closed, never fail open.
    const auto far_future = at(2030, 1, 1);
    CHECK(!store.is_valid("KEY-2026-09-05", far_future));
    CHECK(!store.is_valid("KEY-2030-01-01", far_future));
    std::remove(path.c_str());
}

void coverage_range_is_reported() {
    const std::string path = "day_key_store_test_6.sqlite";
    write_test_db(path, consecutive_days(std::chrono::sys_days{std::chrono::year{2026} /
                                                               std::chrono::September / 1}, 10));
    DayKeyStore store(path);
    CHECK(store.size() == 10);
    CHECK(store.first_date() == "2026-09-01");
    CHECK(store.last_date() == "2026-09-10");
    std::remove(path.c_str());
}

void missing_database_file_throws() {
    bool threw = false;
    try {
        DayKeyStore store("this_file_does_not_exist_12345.sqlite");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

void empty_table_throws() {
    const std::string path = "day_key_store_test_7.sqlite";
    write_test_db(path, {});
    bool threw = false;
    try {
        DayKeyStore store(path);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    std::remove(path.c_str());
}

void malformed_stamp_throws() {
    const std::string path = "day_key_store_test_8.sqlite";
    write_test_db(path, {{"2026-09-01", "GOOD"}, {"not-a-date", "BAD"}});
    bool threw = false;
    try {
        DayKeyStore store(path);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    std::remove(path.c_str());
}

/**
 * The pre-0.9.0 day-of-year schema must fail LOUD, not load as an empty/partial store. Deploying a
 * new binary against an old database would otherwise silently 500 every gated request.
 */
void legacy_day_of_year_schema_throws() {
    const std::string path = "day_key_store_test_9.sqlite";
    std::remove(path.c_str());
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db,
                       "CREATE TABLE day_keys (day_of_year INTEGER PRIMARY KEY, guid TEXT NOT NULL)",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "INSERT INTO day_keys VALUES (1, 'OLD-SCHEME')", nullptr, nullptr,
                       nullptr) == SQLITE_OK);
    sqlite3_close(db);

    bool threw = false;
    try {
        DayKeyStore store(path);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    std::remove(path.c_str());
}

}  // namespace

int main() {
    today_matches_the_stored_key_for_that_date();
    yesterday_and_tomorrow_are_accepted();
    year_boundary_needs_no_special_case();
    leap_day_has_its_own_key();
    unknown_empty_and_uncovered_dates_are_rejected();
    coverage_range_is_reported();
    missing_database_file_throws();
    empty_table_throws();
    malformed_stamp_throws();
    legacy_day_of_year_schema_throws();
    std::cout << "day_key_store_test: all assertions passed\n";
    return 0;
}
