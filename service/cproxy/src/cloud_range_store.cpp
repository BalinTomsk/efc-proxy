#include "cloud_range_store.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <charconv>
#include <format>
#include <stdexcept>

namespace cproxy {

namespace {

/** RAII for a sqlite3 handle so every throw path below closes it. */
struct SqliteDb {
    sqlite3* db = nullptr;
    ~SqliteDb() {
        if (db != nullptr) sqlite3_close(db);
    }
};

}  // namespace

std::optional<std::uint32_t> parse_ipv4(const std::string& text) {
    std::uint32_t value = 0;
    int octets = 0;
    std::size_t i = 0;
    const std::size_t n = text.size();

    while (i < n && octets < 4) {
        if (octets > 0) {
            if (text[i] != '.') return std::nullopt;
            ++i;
        }
        const std::size_t begin = i;
        while (i < n && text[i] >= '0' && text[i] <= '9') ++i;
        // 1..3 digits, and no leading zero on a multi-digit octet (0300 is not 192 here).
        const std::size_t len = i - begin;
        if (len == 0 || len > 3) return std::nullopt;
        if (len > 1 && text[begin] == '0') return std::nullopt;

        unsigned int octet = 0;
        const auto [ptr, ec] = std::from_chars(text.data() + begin, text.data() + i, octet);
        if (ec != std::errc{} || octet > 255) return std::nullopt;
        value = (value << 8) | octet;
        ++octets;
    }

    // Trailing junk (a port, a CIDR suffix, an IPv6 tail) means this is not a bare IPv4 address.
    if (octets != 4 || i != n) return std::nullopt;
    return value;
}

std::optional<IpRange> cidr_to_range(const std::string& cidr) {
    const std::size_t slash = cidr.find('/');
    if (slash == std::string::npos) return std::nullopt;

    const auto base = parse_ipv4(cidr.substr(0, slash));
    if (!base) return std::nullopt;

    const std::string prefix_text = cidr.substr(slash + 1);
    if (prefix_text.empty() || prefix_text.size() > 2) return std::nullopt;
    unsigned int prefix = 0;
    const auto [ptr, ec] =
        std::from_chars(prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
    if (ec != std::errc{} || ptr != prefix_text.data() + prefix_text.size() || prefix > 32) {
        return std::nullopt;
    }

    // /0 would shift a 32-bit value by 32 (undefined), so the whole-space case is spelled out.
    const std::uint32_t size_minus_one =
        prefix == 0 ? 0xFFFFFFFFu : (prefix == 32 ? 0u : (0xFFFFFFFFu >> prefix));
    const std::uint32_t start = *base & ~size_minus_one;
    return IpRange{start, static_cast<std::uint32_t>(start + size_minus_one)};
}

std::vector<IpRange> coalesce_ranges(std::vector<IpRange> ranges) {
    if (ranges.empty()) return ranges;
    std::sort(ranges.begin(), ranges.end(), [](const IpRange& a, const IpRange& b) {
        return a.start != b.start ? a.start < b.start : a.end < b.end;
    });

    std::vector<IpRange> merged;
    merged.reserve(ranges.size());
    merged.push_back(ranges.front());
    for (std::size_t i = 1; i < ranges.size(); ++i) {
        IpRange& tail = merged.back();
        const IpRange& next = ranges[i];
        // Overlapping, nested, or exactly adjacent (tail.end + 1 == next.start) all fold together.
        // The +1 is guarded so a range ending at 255.255.255.255 cannot wrap around to 0.
        const bool adjacent = tail.end != 0xFFFFFFFFu && next.start == tail.end + 1;
        if (next.start <= tail.end || adjacent) {
            tail.end = std::max(tail.end, next.end);
        } else {
            merged.push_back(next);
        }
    }
    merged.shrink_to_fit();
    return merged;
}

CloudRangeStore::CloudRangeStore()
    : ranges_(std::make_shared<const std::vector<IpRange>>()) {}

void CloudRangeStore::replace(std::vector<IpRange> ranges) {
    ranges_.store(std::make_shared<const std::vector<IpRange>>(coalesce_ranges(std::move(ranges))));
}

void CloudRangeStore::reload(const std::string& db_path) {
    SqliteDb handle;
    if (sqlite3_open_v2(db_path.c_str(), &handle.db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        const std::string msg = handle.db != nullptr ? sqlite3_errmsg(handle.db) : "unknown error";
        throw std::runtime_error(
            std::format("failed to open cloud-range database '{}': {}", db_path, msg));
    }

    sqlite3_stmt* stmt = nullptr;
    static const char* const sql =
        "SELECT ip_start, ip_end FROM cloud_provider_ip_range WHERE disabled = 0";
    if (sqlite3_prepare_v2(handle.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::format("failed to query cloud-range database '{}': {}",
                                             db_path, sqlite3_errmsg(handle.db)));
    }

    std::vector<IpRange> loaded;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const sqlite3_int64 start = sqlite3_column_int64(stmt, 0);
        const sqlite3_int64 end = sqlite3_column_int64(stmt, 1);
        // A row outside the 32-bit space, or inverted, is corrupt data — skip it rather than let it
        // widen the blocked set. Blocking too much is the failure mode that takes the site down.
        if (start < 0 || end < start || end > 0xFFFFFFFFLL) continue;
        loaded.push_back(IpRange{static_cast<std::uint32_t>(start),
                                 static_cast<std::uint32_t>(end)});
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        throw std::runtime_error(
            std::format("cloud-range database '{}' query did not complete cleanly", db_path));
    }
    replace(std::move(loaded));
}

bool CloudRangeStore::is_blocked(std::uint32_t ip) const {
    const auto snapshot = ranges_.load();
    if (!snapshot || snapshot->empty()) return false;

    // First interval whose start is > ip; the candidate is the one before it.
    const auto it = std::upper_bound(snapshot->begin(), snapshot->end(), ip,
                                     [](std::uint32_t value, const IpRange& r) {
                                         return value < r.start;
                                     });
    if (it == snapshot->begin()) return false;
    const IpRange& candidate = *(it - 1);
    return ip <= candidate.end;
}

bool CloudRangeStore::is_blocked(const std::string& ip_text) const {
    const auto ip = parse_ipv4(ip_text);
    if (!ip) return false;  // IPv6 / unparsable peer: out of scope, never blocked
    return is_blocked(*ip);
}

std::size_t CloudRangeStore::size() const {
    const auto snapshot = ranges_.load();
    return snapshot ? snapshot->size() : 0;
}

void ensure_cloud_range_schema(const std::string& db_path) {
    SqliteDb handle;
    if (sqlite3_open_v2(db_path.c_str(), &handle.db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        const std::string msg = handle.db != nullptr ? sqlite3_errmsg(handle.db) : "unknown error";
        throw std::runtime_error(
            std::format("failed to open cloud-range database '{}': {}", db_path, msg));
    }

    static const char* const ddl =
        "CREATE TABLE IF NOT EXISTS cloud_provider_ip_range ("
        "  provider    TEXT    NOT NULL,"
        "  cidr        TEXT    NOT NULL,"
        "  ip_start    INTEGER NOT NULL,"
        "  ip_end      INTEGER NOT NULL,"
        "  disabled    INTEGER NOT NULL DEFAULT 0,"
        "  source      TEXT    NOT NULL DEFAULT 'cproxy-refresh',"
        "  updated_utc TEXT    NOT NULL,"
        "  PRIMARY KEY (provider, cidr)"
        ");"
        "CREATE INDEX IF NOT EXISTS ix_cpir_ip_start"
        "  ON cloud_provider_ip_range (ip_start) WHERE disabled = 0;";

    char* err = nullptr;
    if (sqlite3_exec(handle.db, ddl, nullptr, nullptr, &err) != SQLITE_OK) {
        const std::string msg = err != nullptr ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error(
            std::format("failed to create cloud-range schema in '{}': {}", db_path, msg));
    }
}

}  // namespace cproxy
