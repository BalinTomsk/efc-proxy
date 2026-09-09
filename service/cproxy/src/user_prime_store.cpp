#include "user_prime_store.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>

namespace cproxy {

namespace {

struct SqliteDb {
    sqlite3* db = nullptr;
    ~SqliteDb() {
        if (db != nullptr) sqlite3_close(db);
    }
};

/** 128-bit product rendered as decimal digits. unsigned __int128 is a GCC/Clang extension, which is
 *  the whole toolchain this service builds with (Debian trixie, gcc), and the only type here that
 *  cannot overflow on two bigint primes. */
std::string product_decimal(std::int64_t a, std::int64_t b) {
    unsigned __int128 value = static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b);
    if (value == 0) return "0";
    char buffer[40];
    int i = sizeof(buffer);
    while (value > 0) {
        buffer[--i] = static_cast<char>('0' + static_cast<int>(value % 10));
        value /= 10;
    }
    return std::string(buffer + i, sizeof(buffer) - i);
}

bool all_digits(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(),
                                     [](unsigned char c) { return c >= '0' && c <= '9'; });
}

std::string utc_date(std::chrono::system_clock::time_point tp) {
    return std::format("{:%F}", std::chrono::floor<std::chrono::days>(tp));
}

}  // namespace

UserPrimeStore::UserPrimeStore(std::string db_path, int cache_seconds)
    : db_path_(std::move(db_path)),
      // A non-positive TTL would mean "reload on every request", which is a footgun rather than a
      // feature (one SQLite open + join per gated call); clamp it to one second.
      cache_ttl_(std::chrono::seconds(cache_seconds > 0 ? cache_seconds : 1)) {}

int UserPrimeStore::day_of_year(std::chrono::system_clock::time_point tp) {
    const auto days = std::chrono::floor<std::chrono::days>(tp);
    const std::chrono::year_month_day ymd{days};
    const auto jan1 = std::chrono::sys_days{ymd.year() / std::chrono::January / 1};
    const int index = static_cast<int>((days - jan1).count()) + 1;  // 1-based, like day_year
    // 366 clamps to 365: the allocator issues exactly 365 primes per account, so 31 December of a
    // leap year shares 30 December's prime. Same clamp on both sides of the wire.
    return index > 365 ? 365 : index;
}

void UserPrimeStore::refresh(std::chrono::system_clock::time_point now) { load(now); }

std::size_t UserPrimeStore::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return products_.size();
}

std::string UserPrimeStore::last_error() const {
    std::lock_guard<std::mutex> lock(mu_);
    return last_error_;
}

bool UserPrimeStore::is_valid(const std::string& product,
                              std::chrono::system_clock::time_point now) {
    // Rejected before any lookup: the claim is a decimal product, so anything else is either a
    // malformed token or someone probing with a crafted value.
    if (!all_digits(product)) return false;
    refresh_if_stale(now);
    std::lock_guard<std::mutex> lock(mu_);
    return products_.count(product) > 0;
}

void UserPrimeStore::refresh_if_stale(std::chrono::system_clock::time_point now) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        const bool fresh = loaded_ && (now - loaded_at_) < cache_ttl_ &&
                           loaded_day_ == day_of_year(now);
        if (fresh) return;
    }
    load(now);
}

void UserPrimeStore::load(std::chrono::system_clock::time_point now) {
    const int today = day_of_year(now);
    const auto one_day = std::chrono::days{1};
    // The same yesterday/today/tomorrow window DayKeyStore uses. Computed from real dates rather than
    // today±1 so the year boundary wraps correctly (1 January accepts day 365).
    const int yesterday = day_of_year(now - one_day);
    const int tomorrow = day_of_year(now + one_day);
    const std::string today_date = utc_date(now);

    std::unordered_set<std::string> products;
    std::string error;

    SqliteDb handle;
    // Read-only: this process is a consumer of the mirror here, and opening read-write would create
    // an empty database file if the path were wrong, which would then look like "no accounts" rather
    // than "misconfigured".
    if (sqlite3_open_v2(db_path_.c_str(), &handle.db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        error = std::format("failed to open account mirror '{}': {}", db_path_,
                            handle.db != nullptr ? sqlite3_errmsg(handle.db) : "unknown error");
    } else {
        sqlite3_stmt* stmt = nullptr;
        // prime_expired is a calendar date stored verbatim as "yyyy-MM-dd", so a lexicographic
        // comparison IS a chronological one; NULL means the column predates the mirror event that
        // carries it and must not exclude the account.
        static const char* const sql =
            "SELECT s.prime, p.prime "
            "FROM user_prime_sync p "
            "JOIN users_sync s ON s.id = p.user_id "
            "WHERE p.day_year IN (?, ?, ?) "
            "  AND p.prime > 0 AND s.prime > 0 "
            "  AND s.deleted = 0 AND s.suspended = 0 "
            "  AND (s.prime_expired IS NULL OR s.prime_expired = '' OR s.prime_expired >= ?)";
        if (sqlite3_prepare_v2(handle.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            error = std::format("failed to query account mirror '{}': {}", db_path_,
                                sqlite3_errmsg(handle.db));
        } else {
            sqlite3_bind_int(stmt, 1, yesterday);
            sqlite3_bind_int(stmt, 2, today);
            sqlite3_bind_int(stmt, 3, tomorrow);
            sqlite3_bind_text(stmt, 4, today_date.c_str(), -1, SQLITE_TRANSIENT);

            int rc;
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                products.insert(product_decimal(sqlite3_column_int64(stmt, 0),
                                                sqlite3_column_int64(stmt, 1)));
            }
            sqlite3_finalize(stmt);
            if (rc != SQLITE_DONE) {
                error = std::format("account mirror '{}' query did not complete cleanly", db_path_);
                products.clear();
            }
        }
    }

    std::lock_guard<std::mutex> lock(mu_);
    // A failed load installs an EMPTY set on purpose — fail closed. The alternative, keeping the
    // previous snapshot, would let a mirror that has become unreadable keep authorising requests
    // indefinitely with nothing but a log line to say so.
    products_ = std::move(products);
    last_error_ = error;
    loaded_at_ = now;
    loaded_day_ = today;
    loaded_ = true;
}

}  // namespace cproxy
