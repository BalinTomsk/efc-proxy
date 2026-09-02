#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace cproxy {

/** Inclusive numeric window for one IPv4 CIDR: a.b.c.d -> a*2^24 + b*2^16 + c*2^8 + d. */
struct IpRange {
    std::uint32_t start = 0;
    std::uint32_t end = 0;
};

/** Parses dotted-quad IPv4. Returns nullopt for IPv6, a port suffix, or anything malformed. */
std::optional<std::uint32_t> parse_ipv4(const std::string& text);

/** Expands "a.b.c.d/p" to its inclusive window. Returns nullopt for IPv6 / malformed input. */
std::optional<IpRange> cidr_to_range(const std::string& cidr);

/**
 * Datacenter / cloud-provider address space, used to refuse REST calls that originate from hosting
 * networks rather than a real client. Mirrors the frontend's `dbo.CloudProviderIpRange`
 * (see aspnet/Account/CLAUDE.md): one row per published CIDR, expanded to an inclusive
 * [ip_start, ip_end] window, with a `disabled` flag as a manual per-row override.
 *
 * Differences from the frontend, both deliberate:
 *
 *  - **The lookup set is held in memory, not queried per request.** The frontend pays one indexed
 *    SQL seek per request; cproxy is the edge and sees every call, so the ~100k ranges (under 1 MB
 *    as pairs of uint32) are loaded once and binary-searched. Refreshes swap the whole snapshot
 *    atomically, so a reader never sees a half-updated set and never blocks on the writer.
 *  - **Ranges are COALESCED at load.** The frontend's single-seek query
 *    (`TOP 1 ... WHERE ipStart <= @n ORDER BY ipStart DESC`, then confirm `@n <= ipEnd`) is only
 *    correct while ranges are disjoint. Across a dozen providers that is an assumption, not a
 *    guarantee — two feeds can publish overlapping space, and one interval nested inside another
 *    would make that query answer "not blocked" for an address that *is* covered. Merging
 *    overlapping and adjacent intervals up front makes the same binary search correct
 *    unconditionally, and shrinks the set.
 *
 * An empty store blocks nothing. That is the fail-safe direction and matches the frontend, where
 * the table starts empty so nothing is refused until the first successful refresh.
 */
class CloudRangeStore {
public:
    CloudRangeStore();

    /**
     * Replaces the in-memory set with the enabled rows of `db_path`. Throws std::runtime_error if
     * the database cannot be opened or queried; the previous snapshot is left untouched in that
     * case, so a failed reload degrades to "keep using what we had", never to "block nothing".
     */
    void reload(const std::string& db_path);

    /** Installs a set directly (used by the refresher after a write, and by tests). */
    void replace(std::vector<IpRange> ranges);

    /** True when `ip` falls inside any enabled range. */
    bool is_blocked(std::uint32_t ip) const;

    /** Convenience overload; a non-IPv4 address is never blocked. */
    bool is_blocked(const std::string& ip_text) const;

    /** Number of coalesced intervals currently loaded. */
    std::size_t size() const;

private:
    // shared_ptr<const> so readers hold a snapshot alive while a refresh swaps in the next one;
    // atomic<> so the swap needs no lock on the read path (this is consulted on EVERY request).
    std::atomic<std::shared_ptr<const std::vector<IpRange>>> ranges_;
};

/** Sorts and merges overlapping/adjacent windows. Exposed for tests. */
std::vector<IpRange> coalesce_ranges(std::vector<IpRange> ranges);

/**
 * Creates the range table if absent. The schema mirrors the frontend's `dbo.CloudProviderIpRange`
 * so the two stay recognisably the same thing: (provider, cidr) identity, the numeric window, the
 * `disabled` override, and a refresh timestamp. The partial index matches the frontend's filtered
 * `IX_CPIR_ipStart ... WHERE disabled = 0`.
 */
void ensure_cloud_range_schema(const std::string& db_path);

}  // namespace cproxy
