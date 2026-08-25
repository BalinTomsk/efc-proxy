#pragma once

#include <array>
#include <chrono>
#include <string>

namespace cproxy {

/**
 * Per-day-of-year credential for the write surface (PATCH). Loaded once at startup from a small
 * read-only SQLite database (`day_keys(day_of_year INTEGER PRIMARY KEY, guid TEXT NOT NULL)`,
 * exactly 365 rows) that ships alongside the proxy's log volume, generated out-of-band and never
 * rebuilt from source — this is a rotating credential, not application data.
 *
 * A caller presents the GUID for "today" (UTC) in the `X-Day-Guid` header on a PATCH request; a
 * three-day window (yesterday/today/tomorrow) is accepted so a request straddling the UTC midnight
 * boundary is never spuriously rejected. There is deliberately no finer-grained scoping than
 * "PATCH" — day-key auth guards the entire write surface, which today is exactly one endpoint.
 */
class DayKeyStore {
public:
    static constexpr int kDays = 365;

    /**
     * Opens `db_path` read-only and loads all 365 rows into memory (a handful of KB — trivial to
     * hold, and avoids re-querying SQLite on every request). Throws std::runtime_error if the file
     * cannot be opened, the query fails, or the table does not have exactly one row for every
     * `day_of_year` in 1..365 — a day-key store must fail LOUD at startup, never silently accept
     * every request because a malformed table came back with fewer rows than expected.
     */
    explicit DayKeyStore(const std::string& db_path);

    /**
     * True when `guid` (case-insensitive) matches the stored key for yesterday, today, or tomorrow,
     * computed in UTC from `now`. A leap year's 366th day reuses day 365's key rather than needing
     * its own row — day-key rotation is a coarse daily control, not a boundary that has to be exact
     * on one extra day every four years.
     */
    bool is_valid(const std::string& guid, std::chrono::system_clock::time_point now) const;

private:
    std::array<std::string, kDays> keys_;  // keys_[0] = day-of-year 1 (Jan 1) ... keys_[364] = day 365
};

}  // namespace cproxy
