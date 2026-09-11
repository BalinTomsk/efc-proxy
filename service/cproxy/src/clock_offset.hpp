#pragma once

#include <atomic>
#include <chrono>

namespace cproxy {

/**
 * A signed correction applied to cproxy's notion of "now" for **credential validation only**.
 *
 * ### Why an offset and not the system clock
 * "Align cproxy's time" cannot mean `clock_settime` here, for three independent reasons, any one of
 * which is fatal:
 *
 *  1. **The container cannot.** `deploy/compose.yml` runs it with `cap_drop: ALL` and
 *     `no-new-privileges`; setting the clock needs `CAP_SYS_TIME`. Granting it would weaken the
 *     hardening of an internet-facing edge to fix a five-second problem.
 *  2. **There is no container clock to set.** Docker shares the host kernel's clock (no time
 *     namespace is in use), so a successful `clock_settime` would move the whole DROPLET's time —
 *     every log line, TLS validity check, and cron job on the box, not just this process.
 *  3. **systemd-timesyncd would undo it** on its next poll, so the "fix" would be transient and the
 *     two clocks would fight.
 *
 * So the correction lives in this process, and deliberately reaches **only** the JWT/day-key
 * validation path (`check_gate_credential`). Log timestamps stay on the real clock, so a line here
 * still lines up with `docker logs`, journald, and the upstream's logs during an incident — the
 * offset is visible as its own log line instead.
 *
 * ### What may move it
 * Only `check_gate_credential`, and only for a request that carries **both** a MAC-verified token
 * whose `user` product the account mirror maps to a live superAdmin (`access == 255`; the token
 * itself carries no role -- see UserPrimeStore::is_admin) **and** an `X-Client-Time` header. The
 * token authenticates the *caller*; the header supplies the *reading*, because the token's own `iat` cannot: `FishApiJwt` caches a minted
 * token until UTC midnight, so `iat` is routinely hours stale and aligning to it would drag this
 * process backwards by however long ago the admin downloaded `jwt.txt`.
 *
 * ### Bound
 * `adopt` clamps the TOTAL offset, not the per-step delta — a caller cannot walk the clock in small
 * increments past the ceiling. That ceiling is what keeps a replayed admin token from being
 * interesting: `CPROXY_JWT_CLOCK_SYNC_MAX_SECONDS` (default 3600) is far short of the one day a
 * captured token would need to move to make a stale day-key current again, and the day-key store's
 * own +/-1-day window already covers anything smaller.
 *
 * Not persisted: a restart returns to the host clock and re-learns from the next admin request.
 * There is nowhere to persist it to anyway — the container's filesystem is `read_only`.
 */
class ClockOffset {
public:
    /** The corrected time: the system clock plus whatever correction is currently held. */
    std::chrono::system_clock::time_point now() const {
        return std::chrono::system_clock::now() + std::chrono::seconds(offset_.load());
    }

    /**
     * Moves the correction by `delta_seconds` (the gap between a trusted reading and what `now()`
     * currently believes), clamping the resulting TOTAL offset to +/-`max_abs_seconds`.
     *
     * Returns true when the offset actually changed. A clamped-to-unchanged adopt returns false, so
     * the caller can log "refused" rather than reporting a correction that did not happen.
     */
    bool adopt(long long delta_seconds, int max_abs_seconds);

    /** The correction currently applied, in seconds. Positive means cproxy's host clock runs slow. */
    long long offset_seconds() const { return offset_.load(); }

private:
    std::atomic<long long> offset_{0};
};

}  // namespace cproxy
