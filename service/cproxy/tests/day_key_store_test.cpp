// Minimal, framework-free unit tests for the day-key store (SQLite-backed PATCH credential).
// Registered with CTest; run via `ctest --test-dir build` (also executed inside the Docker build).
#include "check.hpp"

#include <sqlite3.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>

#include "day_key_store.hpp"

using namespace cproxy;

namespace {

/** Builds a throwaway SQLite file at `path` with exactly 365 rows, guid[i] for day_of_year i+1. */
void write_test_db(const std::string& path, const std::array<std::string, DayKeyStore::kDays>& guids) {
    std::remove(path.c_str());
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE day_keys (day_of_year INTEGER PRIMARY KEY, guid TEXT NOT NULL)",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "INSERT INTO day_keys (day_of_year, guid) VALUES (?, ?)", -1, &stmt,
                             nullptr) == SQLITE_OK);
    for (int i = 0; i < DayKeyStore::kDays; ++i) {
        sqlite3_reset(stmt);
        sqlite3_bind_int(stmt, 1, i + 1);
        sqlite3_bind_text(stmt, 2, guids[i].c_str(), -1, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(stmt) == SQLITE_DONE);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

std::array<std::string, DayKeyStore::kDays> sequential_guids() {
    std::array<std::string, DayKeyStore::kDays> guids;
    for (int i = 0; i < DayKeyStore::kDays; ++i) {
        guids[i] = "GUID-" + std::to_string(i + 1);
    }
    return guids;
}

std::chrono::system_clock::time_point at_day_of_year(int year, int ordinal) {
    const auto jan1 = std::chrono::sys_days{std::chrono::year{year} / std::chrono::January / 1};
    return std::chrono::sys_days{jan1 + std::chrono::days{ordinal - 1}};
}

void today_matches_the_stored_key_for_that_day() {
    const std::string path = "day_key_store_test_1.sqlite";
    write_test_db(path, sequential_guids());
    DayKeyStore store(path);

    // 2027-03-10 is day-of-year 69 (non-leap year). Valid window is {68, 69, 70}.
    const auto now = at_day_of_year(2027, 69);
    CHECK(store.is_valid("guid-69", now));    // case-insensitive
    CHECK(store.is_valid("GUID-69", now));
    CHECK(!store.is_valid("GUID-71", now));   // outside the yesterday/today/tomorrow window
    std::remove(path.c_str());
}

void yesterday_and_tomorrow_are_accepted_within_the_year() {
    const std::string path = "day_key_store_test_2.sqlite";
    write_test_db(path, sequential_guids());
    DayKeyStore store(path);

    const auto now = at_day_of_year(2027, 100);
    CHECK(store.is_valid("GUID-99", now));   // yesterday
    CHECK(store.is_valid("GUID-100", now));  // today
    CHECK(store.is_valid("GUID-101", now));  // tomorrow
    CHECK(!store.is_valid("GUID-98", now));
    CHECK(!store.is_valid("GUID-102", now));
    std::remove(path.c_str());
}

void year_boundary_wraps_correctly() {
    const std::string path = "day_key_store_test_3.sqlite";
    write_test_db(path, sequential_guids());
    DayKeyStore store(path);

    // 2027-01-01 (day-of-year 1): "yesterday" is Dec 31, 2026 -- day-of-year 365 in ITS year.
    const auto jan1 = at_day_of_year(2027, 1);
    CHECK(store.is_valid("GUID-365", jan1));  // yesterday, wrapped
    CHECK(store.is_valid("GUID-1", jan1));    // today
    CHECK(store.is_valid("GUID-2", jan1));    // tomorrow

    // 2026-12-31 (day-of-year 365): "tomorrow" is Jan 1, 2027 -- day-of-year 1 in ITS year.
    const auto dec31 = at_day_of_year(2026, 365);
    CHECK(store.is_valid("GUID-364", dec31));  // yesterday
    CHECK(store.is_valid("GUID-365", dec31));  // today
    CHECK(store.is_valid("GUID-1", dec31));    // tomorrow, wrapped
    std::remove(path.c_str());
}

void leap_day_366_reuses_day_365s_key() {
    const std::string path = "day_key_store_test_4.sqlite";
    write_test_db(path, sequential_guids());
    DayKeyStore store(path);

    // 2028 is a leap year; Dec 31, 2028 is day-of-year 366.
    const auto leap_day = at_day_of_year(2028, 366);
    CHECK(store.is_valid("GUID-365", leap_day));  // day 366 clamps to the day-365 key
    std::remove(path.c_str());
}

void empty_or_unknown_guid_is_rejected() {
    const std::string path = "day_key_store_test_5.sqlite";
    write_test_db(path, sequential_guids());
    DayKeyStore store(path);

    const auto now = at_day_of_year(2027, 200);
    CHECK(!store.is_valid("", now));
    CHECK(!store.is_valid("not-a-real-key", now));
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

void wrong_row_count_throws() {
    const std::string path = "day_key_store_test_6.sqlite";
    std::remove(path.c_str());
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE day_keys (day_of_year INTEGER PRIMARY KEY, guid TEXT NOT NULL)",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "INSERT INTO day_keys VALUES (1, 'ONLY-ONE-ROW')", nullptr, nullptr,
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
    today_matches_the_stored_key_for_that_day();
    yesterday_and_tomorrow_are_accepted_within_the_year();
    year_boundary_wraps_correctly();
    leap_day_366_reuses_day_365s_key();
    empty_or_unknown_guid_is_rejected();
    missing_database_file_throws();
    wrong_row_count_throws();
    std::cout << "day_key_store_test: all assertions passed\n";
    return 0;
}
