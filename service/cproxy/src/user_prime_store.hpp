#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

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
 * **This class answers yes/no questions, not a who question, and that is deliberate.** `is_valid`
 * and `is_admin` return bools and the query does not even select `users_sync.id`, so the most cproxy
 * can ever conclude is "this product belongs to SOME live account" (and, since 0.12.0, "...which is a
 * superAdmin") — never "this is user X". The gateway therefore does NOT identify the caller and
 * attributes nothing: this is an authorization check, not authentication. Making it identify the
 * caller would mean returning the user id here AND deciding what cproxy does with it (log it? forward
 * it to docapi as a header?) — a real design change, not a tweak, and one that would put an account
 * identifier into logs that currently hold none.
 *
 * ### Admin comes from the mirror, never from the token (0.12.0)
 * `is_admin` is true when the account behind the product has `users_sync.access == 255`, the
 * superAdmin value documented on `dbo.Users.access` in envfish-db and delivered here by the same
 * RabbitMQ users-sync stream as everything else in this table. 0.11.0 briefly trusted an `"adm": true`
 * claim minted by the frontend instead; that put the authority in the token (so anyone holding the
 * signing secret could self-promote) and advertised to every reader of a token that its holder was an
 * admin. Now the claim is ignored and the token carries no such thing — the privilege is looked up
 * here, from data this service already holds, keyed by a `user` product that a secret-holder cannot
 * produce for a real admin without also knowing that admin's primes for today.
 *
 * Note the frontend decides "admin" differently — a GUID list (`AdminUserIds`) rather than `access` —
 * and the two agree today only because both admin accounts hold 255. An account added to that list
 * without `access = 255` is an admin on the portal but not here; that is the fail-safe direction (the
 * only thing it loses is permission to correct cproxy's clock).
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
    /** `dbo.Users.access` value meaning superAdmin (envfish-db script01_createTable.sql). Exact match,
     *  not `>=`: a stray larger value is a data error, and data errors must not grant privilege. */
    static constexpr int kSuperAdminAccess = 255;

    UserPrimeStore(std::string db_path, int cache_seconds);

    /** True when `product` (decimal digits) belongs to an active account for one of the three days
     *  around `now`. Empty or non-numeric input is always false. */
    bool is_valid(const std::string& product, std::chrono::system_clock::time_point now);

    /** True when `product` is valid (as `is_valid`) AND that account's `access` is superAdmin. Same
     *  snapshot, same filters: a suspended, deleted, or expired admin is not an admin here. */
    bool is_admin(const std::string& product, std::chrono::system_clock::time_point now);

    /** Rebuilds the snapshot now, ignoring the TTL. Startup calls this so a mirror that is missing,
     *  empty, or still dormant shows up in the log rather than only as a wall of unexplained 500s. */
    void refresh(std::chrono::system_clock::time_point now);

    /** Size of the current snapshot, for startup/diagnostic logging. Does not trigger a refresh. */
    std::size_t size() const;

    /** How many products in the current snapshot are superAdmin, for the startup log — the one place
     *  an operator can see "clock alignment has someone who may trigger it". Does not refresh. */
    std::size_t admin_count() const;

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
    std::unordered_map<std::string, bool> products_;  // product -> is superAdmin
    std::string last_error_;
    std::chrono::system_clock::time_point loaded_at_{};
    bool loaded_ = false;
    int loaded_day_ = 0;  // day-of-year the snapshot was built for; a rollover forces a reload
};

}  // namespace cproxy
