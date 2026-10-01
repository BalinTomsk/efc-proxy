// McpKeyStore (hashed long-lived MCP client keys) and RateLimiter. Framework-free, like the others.
#include "check.hpp"
#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "mcp_key_store.hpp"
#include "rate_limiter.hpp"

using namespace cproxy;
using namespace std::chrono;

namespace {

struct Row {
    std::string key_id;
    std::string hash;
    std::string label;
    std::optional<std::string> expires;
    int disabled = 0;
};

Row row_for(const std::string& key_id, const std::string& token) {
    return Row{key_id, sha256_hex(token), key_id + " label", std::nullopt, 0};
}

const char* const kSchema =
    "CREATE TABLE mcp_keys (key_id TEXT PRIMARY KEY, token_sha256 TEXT NOT NULL UNIQUE, "
    "label TEXT NOT NULL, created_utc TEXT NOT NULL, expires_utc TEXT NULL, "
    "disabled INTEGER NOT NULL DEFAULT 0)";

void write_db(const std::string& path, const std::vector<Row>& rows, const char* schema = kSchema) {
    std::remove(path.c_str());
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, schema, nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db,
                             "INSERT INTO mcp_keys (key_id, token_sha256, label, created_utc, "
                             "expires_utc, disabled) VALUES (?, ?, ?, '2026-09-30', ?, ?)",
                             -1, &stmt, nullptr) == SQLITE_OK);
    for (const Row& r : rows) {
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, r.key_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, r.hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, r.label.c_str(), -1, SQLITE_TRANSIENT);
        if (r.expires) {
            sqlite3_bind_text(stmt, 4, r.expires->c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 4);
        }
        sqlite3_bind_int(stmt, 5, r.disabled);
        CHECK(sqlite3_step(stmt) == SQLITE_DONE);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

/** Moves the file's mtime forward so a reload is detected regardless of filesystem resolution. */
void bump_mtime(const std::string& path, int seconds) {
    const auto t = std::filesystem::last_write_time(path);
    std::filesystem::last_write_time(path, t + std::chrono::seconds(seconds));
}

bool throws(const std::string& path) {
    try {
        McpKeyStore store(path, 60);
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

std::string temp_path(const char* name) {
    return (std::filesystem::temp_directory_path() / name).string();
}

const auto kNow = sys_days{year{2026} / 9 / 30} + hours{12};

void sha256_matches_the_standard_vector() {
    CHECK(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

void a_known_key_is_found_and_anything_else_is_not() {
    const std::string path = temp_path("mcp_keys_basic.sqlite");
    write_db(path, {row_for("laptop", "ffmcp_secret-one"), row_for("desktop", "ffmcp_secret-two")});
    McpKeyStore store(path, 60);
    CHECK(store.size() == 2);

    const auto k = store.find("ffmcp_secret-one", kNow);
    CHECK(k && k->key_id == "laptop" && k->label == "laptop label");
    CHECK(store.find("ffmcp_secret-two", kNow)->key_id == "desktop");
    CHECK(!store.find("ffmcp_secret-three", kNow));
    CHECK(!store.find("", kNow));
    // The hash, presented as if it were the token, is not the token.
    CHECK(!store.find(sha256_hex("ffmcp_secret-one"), kNow));
    CHECK(!store.find(std::string(10000, 'x'), kNow));
    std::remove(path.c_str());
}

void disabled_and_expired_keys_are_refused() {
    const std::string path = temp_path("mcp_keys_state.sqlite");
    Row off = row_for("off", "t-off");
    off.disabled = 1;
    Row expired = row_for("expired", "t-expired");
    expired.expires = "2026-09-29";
    Row last_day = row_for("last-day", "t-last-day");
    last_day.expires = "2026-09-30";  // inclusive: valid through the end of that UTC day
    write_db(path, {off, expired, last_day});
    McpKeyStore store(path, 60);
    CHECK(store.size() == 2);  // the disabled row is not loaded at all
    CHECK(!store.find("t-off", kNow));
    CHECK(!store.find("t-expired", kNow));
    CHECK(store.find("t-last-day", kNow));
    CHECK(store.find("t-last-day", sys_days{year{2026} / 9 / 30} + hours{23} + minutes{59}));
    CHECK(!store.find("t-last-day", sys_days{year{2026} / 10 / 1}));
    std::remove(path.c_str());
}

void an_upper_case_hash_in_the_file_still_matches() {
    const std::string path = temp_path("mcp_keys_case.sqlite");
    Row r = row_for("upper", "t-upper");
    for (char& c : r.hash) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    write_db(path, {r});
    McpKeyStore store(path, 60);
    CHECK(store.find("t-upper", kNow));
    std::remove(path.c_str());
}

void an_empty_table_is_valid_and_refuses_everything() {
    const std::string path = temp_path("mcp_keys_empty.sqlite");
    write_db(path, {});
    McpKeyStore store(path, 60);
    CHECK(store.size() == 0);
    CHECK(!store.find("anything", kNow));
    std::remove(path.c_str());
}

void a_malformed_file_fails_the_first_load() {
    CHECK(throws(temp_path("mcp_keys_does_not_exist.sqlite")));

    const std::string bad_hash = temp_path("mcp_keys_bad_hash.sqlite");
    write_db(bad_hash, {Row{"k", "not-a-hash", "l", std::nullopt, 0}});
    CHECK(throws(bad_hash));
    std::remove(bad_hash.c_str());

    const std::string bad_date = temp_path("mcp_keys_bad_date.sqlite");
    Row r = row_for("k", "t");
    r.expires = "2026-02-30";
    write_db(bad_date, {r});
    CHECK(throws(bad_date));
    std::remove(bad_date.c_str());

    const std::string wrong_table = temp_path("mcp_keys_wrong_table.sqlite");
    std::remove(wrong_table.c_str());
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(wrong_table.c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE day_keys (stamp TEXT, guid TEXT)", nullptr, nullptr, nullptr) ==
          SQLITE_OK);
    sqlite3_close(db);
    CHECK(throws(wrong_table));
    std::remove(wrong_table.c_str());
}

void a_changed_file_is_reloaded_so_a_key_can_be_revoked_live() {
    const std::string path = temp_path("mcp_keys_reload.sqlite");
    write_db(path, {row_for("a", "t-a")});
    McpKeyStore store(path, 0);  // check the mtime on every lookup
    CHECK(store.find("t-a", kNow));
    CHECK(!store.find("t-b", kNow));

    // Add b, revoke a.
    Row a = row_for("a", "t-a");
    a.disabled = 1;
    write_db(path, {a, row_for("b", "t-b")});
    bump_mtime(path, 5);
    CHECK(!store.find("t-a", kNow));
    CHECK(store.find("t-b", kNow));
    CHECK(store.last_error().empty());
    std::remove(path.c_str());
}

void a_broken_replacement_keeps_the_last_good_keys() {
    const std::string path = temp_path("mcp_keys_broken.sqlite");
    write_db(path, {row_for("a", "t-a")});
    McpKeyStore store(path, 0);
    CHECK(store.find("t-a", kNow));

    write_db(path, {Row{"a", "garbage", "l", std::nullopt, 0}});
    bump_mtime(path, 5);
    CHECK(store.find("t-a", kNow));
    CHECK(!store.last_error().empty());

    // A fixed file is picked up again and clears the error.
    write_db(path, {row_for("b", "t-b")});
    bump_mtime(path, 10);
    CHECK(store.find("t-b", kNow));
    CHECK(!store.find("t-a", kNow));
    CHECK(store.last_error().empty());
    std::remove(path.c_str());
}

void the_reload_interval_is_honoured() {
    const std::string path = temp_path("mcp_keys_interval.sqlite");
    write_db(path, {row_for("a", "t-a")});
    McpKeyStore store(path, 3600);
    write_db(path, {row_for("b", "t-b")});
    bump_mtime(path, 5);
    // Within the interval the file is not looked at again.
    CHECK(store.find("t-a", kNow));
    CHECK(!store.find("t-b", kNow));
    std::remove(path.c_str());
}

void the_bucket_allows_a_burst_then_refills_at_the_rate() {
    RateLimiter limiter(60, 3);  // one token a second, three at most
    const auto t0 = steady_clock::time_point{} + hours{1};
    int retry = 0;
    CHECK(limiter.allow("k", t0, retry));
    CHECK(limiter.allow("k", t0, retry));
    CHECK(limiter.allow("k", t0, retry));
    CHECK(!limiter.allow("k", t0, retry));
    CHECK(retry == 1);
    // Another key has its own bucket.
    CHECK(limiter.allow("other", t0, retry));
    // One second later exactly one more.
    CHECK(limiter.allow("k", t0 + seconds{1}, retry));
    CHECK(!limiter.allow("k", t0 + seconds{1}, retry));
    // A long idle refills only up to the burst, never beyond it.
    const auto later = t0 + hours{1};
    CHECK(limiter.allow("k", later, retry));
    CHECK(limiter.allow("k", later, retry));
    CHECK(limiter.allow("k", later, retry));
    CHECK(!limiter.allow("k", later, retry));
}

void a_slow_rate_reports_a_longer_retry() {
    RateLimiter limiter(6, 1);  // one token every ten seconds
    const auto t0 = steady_clock::time_point{} + hours{1};
    int retry = 0;
    CHECK(limiter.allow("k", t0, retry));
    CHECK(!limiter.allow("k", t0, retry));
    CHECK(retry == 10);
    CHECK(!limiter.allow("k", t0 + seconds{4}, retry));
    CHECK(retry >= 5 && retry <= 7);  // ~6 s left; float rounding may land either side
}

}  // namespace

int main() {
    sha256_matches_the_standard_vector();
    a_known_key_is_found_and_anything_else_is_not();
    disabled_and_expired_keys_are_refused();
    an_upper_case_hash_in_the_file_still_matches();
    an_empty_table_is_valid_and_refuses_everything();
    a_malformed_file_fails_the_first_load();
    a_changed_file_is_reloaded_so_a_key_can_be_revoked_live();
    a_broken_replacement_keeps_the_last_good_keys();
    the_reload_interval_is_honoured();
    the_bucket_allows_a_burst_then_refills_at_the_rate();
    a_slow_rate_reports_a_longer_retry();
    std::cout << "mcp_key_store_test: all assertions passed\n";
    return 0;
}
