#pragma once

#include <chrono>
#include <string>
#include <unordered_map>

namespace cproxy {

/**
 * Per-DAY rotating credential for the gated surface, loaded from a small read-only SQLite database
 * (`day_keys(stamp TEXT PRIMARY KEY, guid TEXT NOT NULL)`) that ships alongside the proxy's volume.
 * Generated out-of-band and never rebuilt from source — this is a rotating credential, not
 * application data.
 *
 * A caller presents the current UTC day's GUID as the `server` claim of its signed Bearer JWT (the
 * raw `X-Day-Guid` header that used to carry it was removed in 0.13.0); a three-day window
 * (yesterday/today/tomorrow) is accepted so a request straddling the UTC midnight boundary is never
 * spuriously rejected.
 *
 * **Keyed by real DATE (`YYYY-MM-DD`), not day-of-year** (changed 0.9.0). The store previously held
 * exactly 365 rows indexed 1..365 and reused them every year, which meant it could not represent the
 * generated key set: `secret/daykeys.csv` and the `dbo.day_keys` MSSQL table are date-keyed and span
 * ten years, so a 365-row projection agreed with them for only about twelve months before drifting.
 * Matching on the date makes every consumer agree by construction, and deletes two pieces of
 * special-case logic the day-of-year scheme needed: the leap-day clamp (day 366 reusing day 365's
 * key) and the year-boundary wrap.
 *
 * The store is deliberately NOT validated against the wall clock at construction — that would couple
 * loading to "now" and make the class untestable with fixed dates. Coverage is exposed through
 * `size()` / `first_date()` / `last_date()` so startup can log the range; a request for a date the
 * store does not cover simply fails closed, like any wrong key.
 */
class DayKeyStore {
public:
    /**
     * Opens `db_path` read-only and loads every row into memory (a few hundred KB at ten years —
     * trivial to hold, and avoids re-querying SQLite on every request). Throws std::runtime_error if
     * the file cannot be opened, the query fails, or the table is empty or malformed (an empty stamp
     * or guid, or a stamp that is not `YYYY-MM-DD`). A day-key store must fail LOUD at startup rather
     * than silently accept or reject everything because the table came back in a shape it did not
     * expect.
     */
    explicit DayKeyStore(const std::string& db_path);

    /**
     * True when `guid` (case-insensitive) matches the stored key for yesterday, today, or tomorrow,
     * computed in UTC from `now`. A date absent from the store matches nothing.
     */
    bool is_valid(const std::string& guid, std::chrono::system_clock::time_point now) const;

    /** Number of dates loaded. */
    std::size_t size() const { return keys_.size(); }

    /** Earliest / latest stamp in the store ("YYYY-MM-DD"), for startup logging. Empty if no rows. */
    const std::string& first_date() const { return first_; }
    const std::string& last_date() const { return last_; }

private:
    std::unordered_map<std::string, std::string> keys_;  // "YYYY-MM-DD" -> upper-cased GUID
    std::string first_;
    std::string last_;
};

/** Formats a UTC time point as "YYYY-MM-DD". Exposed for tests. */
std::string utc_date_string(std::chrono::system_clock::time_point tp);

}  // namespace cproxy
