#include "day_key_store.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <format>
#include <stdexcept>

namespace cproxy {

namespace {

std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
        return std::tolower(x) == std::tolower(y);
    });
}

/** 1-based ordinal day (1..365/366) of the civil UTC date `days` falls on, within its own year. */
int day_of_year(std::chrono::sys_days days) {
    const std::chrono::year_month_day ymd{days};
    const auto jan1 = std::chrono::sys_days{ymd.year() / std::chrono::January / 1};
    return static_cast<int>((days - jan1).count()) + 1;
}

/** Maps a real ordinal day onto the 1..365 key table; only day 366 (a leap year) needs clamping. */
int table_index(int ordinal) {
    const int clamped = ordinal > DayKeyStore::kDays ? DayKeyStore::kDays : ordinal;
    return clamped - 1;
}

}  // namespace

DayKeyStore::DayKeyStore(const std::string& db_path) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(db_path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        const std::string msg = db != nullptr ? sqlite3_errmsg(db) : "unknown error";
        if (db != nullptr) sqlite3_close(db);
        throw std::runtime_error(
            std::format("failed to open day-key database '{}': {}", db_path, msg));
    }

    sqlite3_stmt* stmt = nullptr;
    static const char* const sql = "SELECT day_of_year, guid FROM day_keys ORDER BY day_of_year";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        const std::string msg = sqlite3_errmsg(db);
        sqlite3_close(db);
        throw std::runtime_error(
            std::format("failed to query day-key database '{}': {}", db_path, msg));
    }

    std::array<bool, kDays> seen{};
    int rows = 0;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const int day = sqlite3_column_int(stmt, 0);
        const unsigned char* text = sqlite3_column_text(stmt, 1);
        const std::string guid = text != nullptr ? reinterpret_cast<const char*>(text) : "";
        if (day < 1 || day > kDays || guid.empty()) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            throw std::runtime_error(std::format(
                "day-key database '{}' has an out-of-range or empty row (day_of_year={})",
                db_path, day));
        }
        keys_[day - 1] = to_upper(guid);
        seen[day - 1] = true;
        ++rows;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (rc != SQLITE_DONE) {
        throw std::runtime_error(
            std::format("day-key database '{}' query did not complete cleanly", db_path));
    }
    if (rows != kDays || std::any_of(seen.begin(), seen.end(), [](bool b) { return !b; })) {
        throw std::runtime_error(std::format(
            "day-key database '{}' must have exactly {} rows, one per day_of_year 1..{} — found {}",
            db_path, kDays, kDays, rows));
    }
}

bool DayKeyStore::is_valid(const std::string& guid, std::chrono::system_clock::time_point now) const {
    if (guid.empty()) return false;
    const std::string upper = to_upper(guid);

    const std::chrono::sys_days today = std::chrono::floor<std::chrono::days>(now);
    const int yesterday_ord = day_of_year(today - std::chrono::days{1});
    const int today_ord = day_of_year(today);
    const int tomorrow_ord = day_of_year(today + std::chrono::days{1});

    for (int ordinal : {yesterday_ord, today_ord, tomorrow_ord}) {
        if (iequals(keys_[table_index(ordinal)], upper)) return true;
    }
    return false;
}

}  // namespace cproxy
