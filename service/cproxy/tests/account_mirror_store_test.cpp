#include "check.hpp"
#include <cstdio>
#include <iostream>

#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include "account_mirror_store.hpp"

using namespace cproxy;

namespace {

int count_rows(sqlite3* db, const char* table) {
    sqlite3_stmt* stmt = nullptr;
    std::string sql = std::string("SELECT COUNT(*) FROM ") + table;
    CHECK(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

void applies_user_and_api_key_events_idempotently() {
    const std::string db_path = "account_mirror_store_test.sqlite";
    std::remove(db_path.c_str());

    AccountMirrorStore store(db_path);
    store.ensure_schema();

    nlohmann::json user = {
        {"eventId", "evt-user-1"},
        {"eventType", "fishfind.account.user"},
        {"action", "registered"},
        {"aggregateId", "user-1"},
        {"occurredUtc", "2026-09-03T18:00:00Z"},
        {"user", {{"id", "user-1"}, {"userName", "Ada"}, {"email", "ada@example.test"},
                  {"firstName", "Ada"}, {"lastName", "Lovelace"}, {"country", "CA"},
                  {"postal", "N2M5L4"}, {"authType", "Local"}, {"provider", ""}}}
    };
    CHECK(store.apply_event(user));
    CHECK(!store.apply_event(user));

    nlohmann::json key = {
        {"eventId", "evt-key-1"},
        {"eventType", "fishfind.account.api_key"},
        {"action", "issued"},
        {"aggregateId", "key-1"},
        {"occurredUtc", "2026-09-03T18:01:00Z"},
        {"apiKey", {{"keyId", "key-1"}, {"userId", "user-1"}, {"apiKey", "secret-1"},
                    {"createdUtc", "2026-09-03T18:01:00Z"}, {"expiresUtc", "2026-12-02T18:01:00Z"},
                    {"isDisabled", false}, {"isExpired", false}}}
    };
    CHECK(store.apply_event(key));

    sqlite3* db = nullptr;
    CHECK(sqlite3_open(db_path.c_str(), &db) == SQLITE_OK);
    CHECK(count_rows(db, "account_events") == 2);
    CHECK(count_rows(db, "users") == 1);
    CHECK(count_rows(db, "user_api_key") == 1);
    sqlite3_close(db);

    std::remove(db_path.c_str());
}

// dbo.Users full-row mirror fed by the fishfind-frontend RabbitMQ users-sync dispatcher
// (Run-UsersSyncDispatch.ps1 -> dbo.UsersSyncOutbox -> dbo.TR_Users_SyncOutbox). Covers: the
// 'created' snapshot lands with every field, a later 'updated' event for the same user (e.g. an
// admin suspending the account directly in SQL) upserts in place rather than duplicating the row,
// and duplicate delivery of the same eventId is a no-op (shared account_events dedup table).
void applies_user_sync_events_idempotently_and_upserts_on_update() {
    const std::string db_path = "account_mirror_store_test_usersync.sqlite";
    std::remove(db_path.c_str());

    AccountMirrorStore store(db_path);
    store.ensure_schema();

    nlohmann::json created = {
        {"schema", "fishfind.account-event.v1"},
        {"eventId", "usersync-1"},
        {"eventType", "fishfind.account.user_sync"},
        {"action", "created"},
        {"aggregateId", "user-sync-1"},
        {"occurredUtc", "2026-09-03T18:00:00Z"},
        {"source", "fishfind-frontend"},
        {"user", {{"id", "user-sync-1"}, {"usersId", 3201}, {"userName", "Ada"},
                  {"email", "ada.sync@example.test"}, {"lastVisit", "2026-09-03T17:00:00Z"},
                  {"access", 0}, {"suspended", false}, {"authType", "Local"},
                  {"deleted", false}, {"deletedUtc", nullptr},
                  // prime is 0 on 'created': the Users row is written before sp_user_prime_assign
                  // issues the prime, and the allocating UPDATE emits a second outbox event.
                  {"prime", 0}, {"primeExpired", "2027-09-03"}}}
    };
    CHECK(store.apply_event(created));
    CHECK(!store.apply_event(created));  // duplicate eventId is a no-op

    // A manual admin UPDATE dbo.Users SET suspended = 1 (no app code path for this today) produces
    // a distinct outbox row / eventId with action 'updated' -- must upsert onto the SAME row.
    nlohmann::json updated = {
        {"schema", "fishfind.account-event.v1"},
        {"eventId", "usersync-2"},
        {"eventType", "fishfind.account.user_sync"},
        {"action", "updated"},
        {"aggregateId", "user-sync-1"},
        {"occurredUtc", "2026-09-03T18:05:00Z"},
        {"source", "fishfind-frontend"},
        {"user", {{"id", "user-sync-1"}, {"usersId", 3201}, {"userName", "Ada"},
                  {"email", "ada.sync@example.test"}, {"lastVisit", "2026-09-03T17:00:00Z"},
                  {"access", 0}, {"suspended", true}, {"authType", "Local"},
                  {"deleted", false}, {"deletedUtc", nullptr},
                  // The allocated prime, as it lands on the follow-up event.
                  {"prime", 1000037}, {"primeExpired", "2027-09-03"}}}
    };
    CHECK(store.apply_event(updated));

    sqlite3* db = nullptr;
    CHECK(sqlite3_open(db_path.c_str(), &db) == SQLITE_OK);
    CHECK(count_rows(db, "account_events") == 2);  // one per eventId, not per apply_event call
    CHECK(count_rows(db, "users_sync") == 1);       // upserted onto the same id, not duplicated

    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db,
                             "SELECT users_id, suspended, access, prime, prime_expired "
                             "FROM users_sync WHERE id = 'user-sync-1'",
                             -1, &stmt, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    CHECK(sqlite3_column_int(stmt, 0) == 3201);
    CHECK(sqlite3_column_int(stmt, 1) == 1);  // suspended reflects the later 'updated' event
    CHECK(sqlite3_column_int(stmt, 2) == 0);
    // The prime allocated by the follow-up event overwrites the 0 the 'created' event carried --
    // this is the whole point of routing prime through the same upsert rather than a first-write-wins
    // path, since a new account's FIRST event always carries 0.
    CHECK(sqlite3_column_int64(stmt, 3) == 1000037);
    CHECK(std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))) == "2027-09-03");
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    std::remove(db_path.c_str());
}

// dbo.Users.prime is a bigint and the sequence is global and monotonic, so a mirror binding it as a
// 32-bit int would eventually store a DIFFERENT prime -- and prime is an access-security value, so a
// truncated one is not "roughly right", it is a wrong credential. Same failure mode as
// preserves_users_id_beyond_32_bits, asserted separately because the two are bound independently.
void preserves_prime_beyond_32_bits() {
    const std::string db_path = "account_mirror_store_test_bigprime.sqlite";
    std::remove(db_path.c_str());

    AccountMirrorStore store(db_path);
    store.ensure_schema();

    const std::int64_t big_prime = 4294967311LL;  // the first prime above 2^32

    nlohmann::json created = {
        {"schema", "fishfind.account-event.v1"},
        {"eventId", "usersync-bigprime-1"},
        {"eventType", "fishfind.account.user_sync"},
        {"action", "updated"},
        {"aggregateId", "user-bigprime-1"},
        {"occurredUtc", "2026-09-03T18:00:00Z"},
        {"source", "fishfind-frontend"},
        {"user", {{"id", "user-bigprime-1"}, {"usersId", 42}, {"userName", "Sophie"},
                  {"email", "sophie@example.test"}, {"lastVisit", "2026-09-03T17:00:00Z"},
                  {"access", 0}, {"suspended", false}, {"authType", "Local"},
                  {"deleted", false}, {"deletedUtc", nullptr},
                  {"prime", big_prime}, {"primeExpired", "2027-09-03"}}}
    };
    CHECK(store.apply_event(created));

    sqlite3* db = nullptr;
    CHECK(sqlite3_open(db_path.c_str(), &db) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "SELECT prime FROM users_sync WHERE id = 'user-bigprime-1'",
                             -1, &stmt, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    const std::int64_t stored = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (stored != big_prime) {
        std::cout << "prime truncated: expected " << big_prime << ", stored " << stored << "\n";
    }
    CHECK(stored == big_prime);

    std::remove(db_path.c_str());
}

// ensure_schema() runs against mirror databases that ALREADY EXIST on the droplet, where
// `CREATE TABLE IF NOT EXISTS` does nothing at all. Without the explicit ALTER migration, a new
// column exists only on a freshly created file: every deployed mirror keeps the old shape and the new
// field is silently discarded -- no error, no log line, just a column that is never written. This
// builds the pre-change users_sync by hand and asserts ensure_schema() upgrades it in place and
// preserves the rows that were already there.
void migrates_prime_columns_onto_an_existing_mirror() {
    const std::string db_path = "account_mirror_store_test_migrate.sqlite";
    std::remove(db_path.c_str());

    sqlite3* db = nullptr;
    CHECK(sqlite3_open(db_path.c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db,
                       "CREATE TABLE users_sync ("
                       "  id TEXT PRIMARY KEY,"
                       "  users_id INTEGER NOT NULL DEFAULT 0,"
                       "  user_name TEXT NOT NULL DEFAULT '',"
                       "  email TEXT NOT NULL DEFAULT '',"
                       "  last_visit TEXT NOT NULL DEFAULT '',"
                       "  access INTEGER NOT NULL DEFAULT 0,"
                       "  suspended INTEGER NOT NULL DEFAULT 0,"
                       "  auth_type TEXT NOT NULL DEFAULT '',"
                       "  deleted INTEGER NOT NULL DEFAULT 0,"
                       "  deleted_utc TEXT NULL,"
                       "  updated_utc TEXT NOT NULL"
                       ");"
                       "INSERT INTO users_sync (id, users_id, updated_utc) "
                       "VALUES ('legacy-user-1', 7, '2026-09-01T00:00:00Z');",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(db);

    AccountMirrorStore store(db_path);
    store.ensure_schema();
    store.ensure_schema();  // idempotent: a second run must not fail on "duplicate column name"

    nlohmann::json event = {
        {"schema", "fishfind.account-event.v1"},
        {"eventId", "usersync-migrate-1"},
        {"eventType", "fishfind.account.user_sync"},
        {"action", "updated"},
        {"aggregateId", "legacy-user-1"},
        {"occurredUtc", "2026-09-05T12:00:00Z"},
        {"source", "fishfind-frontend"},
        {"user", {{"id", "legacy-user-1"}, {"usersId", 7}, {"userName", "Legacy"},
                  {"email", "legacy@example.test"}, {"lastVisit", "2026-09-05T11:00:00Z"},
                  {"access", 0}, {"suspended", false}, {"authType", "Local"},
                  {"deleted", false}, {"deletedUtc", nullptr},
                  {"prime", 1000039}, {"primeExpired", "2027-09-05"}}}
    };
    CHECK(store.apply_event(event));

    CHECK(sqlite3_open(db_path.c_str(), &db) == SQLITE_OK);
    CHECK(count_rows(db, "users_sync") == 1);  // upserted onto the pre-existing row, not duplicated
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "SELECT prime, prime_expired FROM users_sync WHERE id = 'legacy-user-1'",
                             -1, &stmt, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    CHECK(sqlite3_column_int64(stmt, 0) == 1000039);
    CHECK(std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) == "2027-09-05");
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    std::remove(db_path.c_str());
}

// A pre-change outbox row replayed after the ALTER has no prime_expired snapshot to offer, so the
// dispatcher emits JSON null. That must land as SQL NULL -- not as the string "null", which
// str_or_empty would produce for any non-string value it did not special-case.
void stores_missing_prime_expired_as_null() {
    const std::string db_path = "account_mirror_store_test_nullprime.sqlite";
    std::remove(db_path.c_str());

    AccountMirrorStore store(db_path);
    store.ensure_schema();

    nlohmann::json event = {
        {"schema", "fishfind.account-event.v1"},
        {"eventId", "usersync-nullprime-1"},
        {"eventType", "fishfind.account.user_sync"},
        {"action", "created"},
        {"aggregateId", "user-nullprime-1"},
        {"occurredUtc", "2026-09-05T12:00:00Z"},
        {"source", "fishfind-frontend"},
        {"user", {{"id", "user-nullprime-1"}, {"usersId", 9}, {"userName", "Old"},
                  {"email", "old@example.test"}, {"lastVisit", "2026-09-05T11:00:00Z"},
                  {"access", 0}, {"suspended", false}, {"authType", "Local"},
                  {"deleted", false}, {"deletedUtc", nullptr},
                  {"prime", 0}, {"primeExpired", nullptr}}}
    };
    CHECK(store.apply_event(event));

    sqlite3* db = nullptr;
    CHECK(sqlite3_open(db_path.c_str(), &db) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db,
                             "SELECT prime, prime_expired IS NULL FROM users_sync WHERE id = 'user-nullprime-1'",
                             -1, &stmt, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    CHECK(sqlite3_column_int64(stmt, 0) == 0);
    CHECK(sqlite3_column_int(stmt, 1) == 1);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    std::remove(db_path.c_str());
}

// dbo.Users.UsersId is `bigint identity(1,128)` on a peer-to-peer replicated database, so each node
// is seeded into its own range and the value routinely exceeds 32 bits -- a node seeded at, say,
// 2^32 hands out ids no int can hold. Binding it as a 32-bit int silently truncates, so the mirror
// would carry a DIFFERENT id than the source row: a wrong join key, not a rounding error.
void preserves_users_id_beyond_32_bits() {
    const std::string db_path = "account_mirror_store_test_bigid.sqlite";
    std::remove(db_path.c_str());

    AccountMirrorStore store(db_path);
    store.ensure_schema();

    const std::int64_t big_users_id = 4294967424LL;  // 2^32 + 128: the next id after a 2^32 seed

    nlohmann::json created = {
        {"schema", "fishfind.account-event.v1"},
        {"eventId", "usersync-bigid-1"},
        {"eventType", "fishfind.account.user_sync"},
        {"action", "created"},
        {"aggregateId", "user-bigid-1"},
        {"occurredUtc", "2026-09-03T18:00:00Z"},
        {"source", "fishfind-frontend"},
        {"user", {{"id", "user-bigid-1"}, {"usersId", big_users_id}, {"userName", "Grace"},
                  {"email", "grace@example.test"}, {"lastVisit", "2026-09-03T17:00:00Z"},
                  {"access", 0}, {"suspended", false}, {"authType", "Local"},
                  {"deleted", false}, {"deletedUtc", nullptr}}}
    };
    CHECK(store.apply_event(created));

    sqlite3* db = nullptr;
    CHECK(sqlite3_open(db_path.c_str(), &db) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "SELECT users_id FROM users_sync WHERE id = 'user-bigid-1'",
                             -1, &stmt, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    const std::int64_t stored = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (stored != big_users_id) {
        std::cout << "users_id truncated: expected " << big_users_id << ", stored " << stored << "\n";
    }
    CHECK(stored == big_users_id);

    std::remove(db_path.c_str());
}

}  // namespace

int main() {
    applies_user_and_api_key_events_idempotently();
    applies_user_sync_events_idempotently_and_upserts_on_update();
    preserves_users_id_beyond_32_bits();
    preserves_prime_beyond_32_bits();
    migrates_prime_columns_onto_an_existing_mirror();
    stores_missing_prime_expired_as_null();
    std::cout << "account_mirror_store_test: all assertions passed\n";
    return 0;
}
