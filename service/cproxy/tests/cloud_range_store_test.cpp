// Unit tests for the datacenter / cloud-provider range store. Framework-free like the rest;
// registered with CTest and run inside the Docker build.
//
// Every address here is from an RFC 5737 documentation range (192.0.2.x, 198.51.100.x, 203.0.113.x)
// or RFC 1918 private space — never a real provider address.
#include "check.hpp"
#include <cstdio>
#include <format>
#include <iostream>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "cloud_range_store.hpp"

using namespace cproxy;

namespace {

std::uint32_t ip(const std::string& s) {
    auto v = parse_ipv4(s);
    CHECK(v.has_value());
    return *v;
}

void ipv4_parsing_accepts_addresses_and_rejects_everything_else() {
    CHECK(ip("0.0.0.0") == 0u);
    CHECK(ip("255.255.255.255") == 0xFFFFFFFFu);
    CHECK(ip("1.2.3.4") == 0x01020304u);
    CHECK(ip("192.0.2.1") == ((192u << 24) | (0u << 16) | (2u << 8) | 1u));

    // Not addresses: IPv6, an octet out of range, a port, a CIDR, junk, and partial forms.
    for (const char* bad : {"::1", "2001:db8::1", "192.0.2.256", "192.0.2.1:8080",
                            "192.0.2.0/24", "192.0.2", "192.0.2.1.5", "", "abc",
                            "192.0.2.-1", " 192.0.2.1"}) {
        CHECK(!parse_ipv4(bad).has_value());
    }
    // A leading zero is rejected rather than silently read as octal or decimal — "0300.0.0.1"
    // must not become a different address than the text suggests.
    CHECK(!parse_ipv4("010.0.0.1").has_value());
}

void cidr_expansion_matches_the_frontend_formula() {
    // /32 is a single address; /24 is 256; /0 is the whole space. Same [start,end] windows the
    // frontend's ConvertTo-IpRange produces.
    auto one = cidr_to_range("192.0.2.7/32");
    CHECK(one && one->start == ip("192.0.2.7") && one->end == ip("192.0.2.7"));

    auto slash24 = cidr_to_range("192.0.2.0/24");
    CHECK(slash24 && slash24->start == ip("192.0.2.0") && slash24->end == ip("192.0.2.255"));

    auto all = cidr_to_range("0.0.0.0/0");
    CHECK(all && all->start == 0u && all->end == 0xFFFFFFFFu);

    // A host bit set below the prefix length is masked off, so 192.0.2.5/24 covers the same /24.
    auto masked = cidr_to_range("192.0.2.5/24");
    CHECK(masked && masked->start == ip("192.0.2.0") && masked->end == ip("192.0.2.255"));

    // IPv6 and malformed input are skipped, exactly as the PowerShell version skips them.
    for (const char* bad : {"2001:db8::/32", "192.0.2.0/33", "192.0.2.0/", "192.0.2.0",
                            "192.0.2.0/abc", ""}) {
        CHECK(!cidr_to_range(bad).has_value());
    }
}

void overlapping_ranges_are_coalesced() {
    // The frontend's single-seek query is only correct for disjoint ranges. These three shapes are
    // exactly what would break it, so the store merges them: a nested interval, an overlap, and
    // two exactly-adjacent blocks.
    const std::vector<IpRange> raw = {
        {ip("192.0.2.0"), ip("192.0.2.255")},       // outer
        {ip("192.0.2.10"), ip("192.0.2.20")},       // nested entirely inside the outer
        {ip("192.0.2.128"), ip("198.51.100.0")},    // overlaps the outer and extends past it
        {ip("198.51.100.1"), ip("198.51.100.9")},   // exactly adjacent -> folds in
    };

    const auto merged = coalesce_ranges(raw);
    CHECK(merged.size() == 1);
    CHECK(merged[0].start == ip("192.0.2.0"));
    CHECK(merged[0].end == ip("198.51.100.9"));

    // Genuinely disjoint blocks stay separate.
    const auto two = coalesce_ranges({{ip("192.0.2.0"), ip("192.0.2.255")},
                                      {ip("203.0.113.0"), ip("203.0.113.255")}});
    CHECK(two.size() == 2);

    // A range ending at the top of the space must not wrap when the adjacency check adds 1.
    const auto top = coalesce_ranges({{ip("255.255.255.0"), 0xFFFFFFFFu}, {0u, 0u}});
    CHECK(top.size() == 2);
    CHECK(top[0].start == 0u && top[0].end == 0u);
}

void lookup_finds_covered_addresses_and_only_those() {
    CloudRangeStore store;
    CHECK(!store.is_blocked(ip("192.0.2.1")));  // empty store blocks nothing (fail-safe)
    CHECK(store.size() == 0);

    store.replace({{ip("192.0.2.0"), ip("192.0.2.255")},
                   {ip("203.0.113.16"), ip("203.0.113.31")}});
    CHECK(store.size() == 2);

    // Inside, and exactly on both boundaries.
    CHECK(store.is_blocked(ip("192.0.2.0")));
    CHECK(store.is_blocked(ip("192.0.2.128")));
    CHECK(store.is_blocked(ip("192.0.2.255")));
    CHECK(store.is_blocked(ip("203.0.113.16")));
    CHECK(store.is_blocked(ip("203.0.113.31")));

    // Immediately outside both, below the first, and above the last.
    CHECK(!store.is_blocked(ip("192.0.1.255")));
    CHECK(!store.is_blocked(ip("192.0.3.0")));
    CHECK(!store.is_blocked(ip("203.0.113.15")));
    CHECK(!store.is_blocked(ip("203.0.113.32")));
    CHECK(!store.is_blocked(ip("0.0.0.1")));
    CHECK(!store.is_blocked(ip("255.255.255.255")));

    // A non-IPv4 peer is never blocked rather than being treated as 0.0.0.0.
    CHECK(!store.is_blocked(std::string("::1")));
    CHECK(!store.is_blocked(std::string("")));
    CHECK(store.is_blocked(std::string("192.0.2.9")));
}

void reload_reads_enabled_rows_only() {
    const std::string db = "cloud_range_store_test.sqlite";
    std::remove(db.c_str());
    ensure_cloud_range_schema(db);

    sqlite3* h = nullptr;
    CHECK(sqlite3_open(db.c_str(), &h) == SQLITE_OK);
    const std::string insert = std::format(
        "INSERT INTO cloud_provider_ip_range (provider, cidr, ip_start, ip_end, disabled,"
        " updated_utc) VALUES"
        " ('Test', '192.0.2.0/24', {}, {}, 0, '2026-01-01T00:00:00Z'),"
        " ('Test', '203.0.113.0/24', {}, {}, 1, '2026-01-01T00:00:00Z');",
        ip("192.0.2.0"), ip("192.0.2.255"), ip("203.0.113.0"), ip("203.0.113.255"));
    CHECK(sqlite3_exec(h, insert.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(h);

    CloudRangeStore store;
    store.reload(db);
    CHECK(store.size() == 1);
    CHECK(store.is_blocked(ip("192.0.2.9")));
    // disabled = 1 is the manual override the frontend documents; it must not block.
    CHECK(!store.is_blocked(ip("203.0.113.9")));

    // A failed reload keeps the previous set rather than silently emptying it — degrading to
    // "block nothing" on a transient read error would quietly switch the protection off.
    bool threw = false;
    try {
        store.reload("definitely_not_a_database_9876.sqlite");
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(store.is_blocked(ip("192.0.2.9")));

    std::remove(db.c_str());
}

}  // namespace

int main() {
    ipv4_parsing_accepts_addresses_and_rejects_everything_else();
    cidr_expansion_matches_the_frontend_formula();
    overlapping_ranges_are_coalesced();
    lookup_finds_covered_addresses_and_only_those();
    reload_reads_enabled_rows_only();
    std::cout << "cloud_range_store_test: all assertions passed\n";
    return 0;
}
