#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_set>

namespace cproxy {

/**
 * Answers "is this JWT `user` claim a live account?" out of cproxy's own account mirror — the SQLite
 * database the RabbitMQ consumer fills from `dbo.Users` / `dbo.Users_Prime` (see AccountMirrorStore).
 * cproxy never queries MSSQL, so this is the only account data it has, by design.
 *
 * The claim is the product `Users.prime * Users_Prime.prime` for the current day of the year, which
 * the frontend computes and this class re-derives:
 *
 *   users_sync.prime  x  user_prime_sync.prime WHERE day_year = <today>
 *
 * Both factors are primes issued exactly once globally (`UK_Users_prime`, `UK_Users_Prime`), so the
 * product identifies one account on one day and reveals neither factor to whoever sees the token.
 *
 * **This class answers a yes/no question, not a who question, and that is deliberate.** `is_valid`
 * returns a bool and the query does not even select `users_sync.id`, so the most cproxy can ever
 * conclude is "this product belongs to SOME live account" — never "this is user X". The gateway
 * therefore does NOT identify the caller and attributes nothing: this is an authorization check, not
 * authentication. Making it identify the caller would mean returning the user id here AND deciding
 * what cproxy does with it (log it? forward it to docapi as a header?) — a real design change, not a
 * tweak, and one that would put an account identifier into logs that currently hold none.
 *
 * **Compared as decimal TEXT, not as an integer.** Each factor is a bigint and the pair routinely
 * multiplies past 2^63, so an int64 product would wrap — silently turning one account's credential
 * into a different valid-looking number. The products are computed in 128-bit arithmetic and matched
 * as strings, which cannot overflow at any account count.
 *
 * ### Day-of-year window
 * `dbo.Users_Prime.day_year` is 1..365 with no calendar attached (the allocator writes 365 primes in
 * order), so a date maps to `tm_yday + 1` clamped to 365 — 31 December of a leap year reuses day 365,
 * the same clamp the allocator's fixed 365-entry block implies. Yesterday/today/tomorrow are all
 * accepted, matching DayKeyStore's window so a request landing on the UTC midnight boundary is never
 * spuriously rejected.
 *
 * ### Snapshot, not a query per request
 * The matching set is materialised into a hash set and refreshed after `cache_seconds`, so a gated
 * request costs one string hash rather than a SQLite open + join. The mirror is eventually consistent
 * already (events arrive over RabbitMQ), so a few seconds of staleness changes nothing about the
 * guarantees — except at one edge worth stating: a suspension or deletion takes up to `cache_seconds`
 * to bite. Keep it short.
 *
 * Suspended, deleted, and prime-expired accounts are excluded, and an account still sitting at
 * `prime = 0` (allocated on the *following* event — see AccountMirrorStore) simply does not match.
 *
 * A missing or unreadable mirror yields an EMPTY set, which matches nothing: this store fails CLOSED
 * like the day-key store, not open like the cloud-range store. It is only consulted when
 * `CPROXY_JWT_REQUIRE_USER` is on, and turning that on is the operator saying the mirror is live.
 */
class UserPrimeStore {
public:
    UserPrimeStore(std::string db_path, int cache_seconds);

    /** True when `product` (decimal digits) belongs to an active account for one of the three days
     *  around `now`. Empty or non-numeric input is always false. */
    bool is_valid(const std::string& product, std::chrono::system_clock::time_point now);

    /** Rebuilds the snapshot now, ignoring the TTL. Startup calls this so a mirror that is missing,
     *  empty, or still dormant shows up in the log rather than only as a wall of unexplained 500s. */
    void refresh(std::chrono::system_clock::time_point now);

    /** Size of the current snapshot, for startup/diagnostic logging. Does not trigger a refresh. */
    std::size_t size() const;

    /** The last refresh's failure message, empty when it succeeded. For logging only. */
    std::string last_error() const;

    /** 1..365 for a UTC time point, 366 clamped to 365. Exposed for tests. */
    static int day_of_year(std::chrono::system_clock::time_point tp);

private:
    void refresh_if_stale(std::chrono::system_clock::time_point now);
    void load(std::chrono::system_clock::time_point now);

    std::string db_path_;
    std::chrono::seconds cache_ttl_;

    mutable std::mutex mu_;
    std::unordered_set<std::string> products_;
    std::string last_error_;
    std::chrono::system_clock::time_point loaded_at_{};
    bool loaded_ = false;
    int loaded_day_ = 0;  // day-of-year the snapshot was built for; a rollover forces a reload
};

}  // namespace cproxy
