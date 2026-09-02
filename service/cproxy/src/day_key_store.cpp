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

/** Accepts exactly "YYYY-MM-DD" with digits in the right places — a cheap shape check, not a
 *  calendar validation: the generator owns correctness, this only catches a wrong column. */
bool looks_like_iso_date(const std::string& s) {
    if (s.size() != 10) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const bool dash = (i == 4 || i == 7);
        if (dash != (s[i] == '-')) return false;
        if (!dash && (s[i] < '0' || s[i] > '9')) return false;
    }
    return true;
}

/** RAII for the sqlite3 handle so every throw path below closes it. */
struct SqliteDb {
    sqlite3* db = nullptr;
    ~SqliteDb() {
        if (db != nullptr) sqlite3_close(db);
    }
};

}  // namespace

std::string utc_date_string(std::chrono::system_clock::time_point tp) {
    return std::format("{:%F}", std::chrono::floor<std::chrono::days>(tp));
}

DayKeyStore::DayKeyStore(const std::string& db_path) {
    SqliteDb handle;
    if (sqlite3_open_v2(db_path.c_str(), &handle.db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        const std::string msg = handle.db != nullptr ? sqlite3_errmsg(handle.db) : "unknown error";
        throw std::runtime_error(
            std::format("failed to open day-key database '{}': {}", db_path, msg));
    }

    sqlite3_stmt* stmt = nullptr;
    static const char* const sql = "SELECT stamp, guid FROM day_keys ORDER BY stamp";
    if (sqlite3_prepare_v2(handle.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        // The most likely cause is the pre-0.9.0 day-of-year schema, so say so explicitly rather
        // than leaving an operator to decode a bare SQLite message.
        throw std::runtime_error(std::format(
            "failed to query day-key database '{}': {} — expected the date-keyed schema "
            "day_keys(stamp TEXT, guid TEXT); a pre-0.9.0 day_of_year table will fail here and must "
            "be regenerated from secret/daykeys.csv",
            db_path, sqlite3_errmsg(handle.db)));
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char* stamp_text = sqlite3_column_text(stmt, 0);
        const unsigned char* guid_text = sqlite3_column_text(stmt, 1);
        const std::string stamp = stamp_text != nullptr ? reinterpret_cast<const char*>(stamp_text) : "";
        const std::string guid = guid_text != nullptr ? reinterpret_cast<const char*>(guid_text) : "";

        if (!looks_like_iso_date(stamp) || guid.empty()) {
            sqlite3_finalize(stmt);
            throw std::runtime_error(std::format(
                "day-key database '{}' has a malformed row (stamp must be YYYY-MM-DD and guid "
                "non-empty)",
                db_path));
        }
        keys_.emplace(stamp, to_upper(guid));
        if (first_.empty() || stamp < first_) first_ = stamp;
        if (stamp > last_) last_ = stamp;
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        throw std::runtime_error(
            std::format("day-key database '{}' query did not complete cleanly", db_path));
    }
    if (keys_.empty()) {
        throw std::runtime_error(std::format("day-key database '{}' contains no rows", db_path));
    }
}

bool DayKeyStore::is_valid(const std::string& guid, std::chrono::system_clock::time_point now) const {
    if (guid.empty()) return false;
    const std::string upper = to_upper(guid);

    // Yesterday / today / tomorrow in UTC. With real dates this needs no year-boundary or leap-day
    // special casing — chrono does the arithmetic and the lookup is an exact string match.
    const auto today = std::chrono::floor<std::chrono::days>(now);
    for (int offset : {-1, 0, 1}) {
        const auto it = keys_.find(utc_date_string(today + std::chrono::days{offset}));
        if (it != keys_.end() && it->second == upper) return true;
    }
    return false;
}

}  // namespace cproxy
