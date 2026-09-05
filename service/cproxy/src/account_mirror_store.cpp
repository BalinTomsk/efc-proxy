#include "account_mirror_store.hpp"

#include <sqlite3.h>

#include <cstdint>
#include <format>
#include <stdexcept>
#include <string>

namespace cproxy {
namespace {

struct SqliteDb {
    sqlite3* db = nullptr;
    ~SqliteDb() {
        if (db != nullptr) sqlite3_close(db);
    }
};

std::string str_or_empty(const nlohmann::json& obj, const char* key) {
    if (!obj.is_object() || !obj.contains(key) || obj[key].is_null()) return {};
    if (obj[key].is_string()) return obj[key].get<std::string>();
    return obj[key].dump();
}

int bool_or_zero(const nlohmann::json& obj, const char* key) {
    if (!obj.is_object() || !obj.contains(key) || obj[key].is_null()) return 0;
    if (obj[key].is_boolean()) return obj[key].get<bool>() ? 1 : 0;
    if (obj[key].is_number_integer()) return obj[key].get<int>() != 0 ? 1 : 0;
    const std::string s = obj[key].is_string() ? obj[key].get<std::string>() : "";
    return (s == "true" || s == "True" || s == "1") ? 1 : 0;
}

void bind_text(sqlite3_stmt* stmt, int index, const std::string& value) {
    sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT);
}

void exec(sqlite3* db, const char* sql, const std::string& context) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        const std::string msg = err != nullptr ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error(context + ": " + msg);
    }
}

bool column_exists(sqlite3* db, const std::string& table, const std::string& column) {
    sqlite3_stmt* stmt = nullptr;
    const std::string sql = std::format("PRAGMA table_info({})", table);
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::format("inspect columns of {}: {}", table, sqlite3_errmsg(db)));
    }
    bool found = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(stmt, 1);  // table_info: cid, name, type, ...
        if (name != nullptr && column == reinterpret_cast<const char*>(name)) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

// `CREATE TABLE IF NOT EXISTS` is a no-op against a mirror database that already exists, so a column
// added to the DDL above only ever appears on a FRESH file -- every deployed mirror would silently
// keep the old shape and the new field would be dropped on the floor with no error anywhere. Adding a
// column has to be an explicit, idempotent migration. SQLite's ALTER TABLE ADD COLUMN is O(1)
// metadata-only and requires the new column to be NULLable or carry a constant default, which both of
// these do.
void add_column_if_missing(sqlite3* db, const std::string& table, const std::string& column,
                           const std::string& decl) {
    if (column_exists(db, table, column)) return;
    const std::string sql = std::format("ALTER TABLE {} ADD COLUMN {} {}", table, column, decl);
    exec(db, sql.c_str(), std::format("add column {}.{}", table, column));
}

class Tx {
public:
    explicit Tx(sqlite3* db) : db_(db) { exec(db_, "BEGIN IMMEDIATE", "begin account mirror transaction"); }
    ~Tx() {
        if (!committed_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
    }
    void commit() {
        exec(db_, "COMMIT", "commit account mirror transaction");
        committed_ = true;
    }

private:
    sqlite3* db_;
    bool committed_ = false;
};

void mark_event(sqlite3* db, const nlohmann::json& event) {
    sqlite3_stmt* stmt = nullptr;
    static const char* const sql =
        "INSERT OR IGNORE INTO account_events "
        "(event_id, event_type, action, aggregate_id, occurred_utc, payload_json, received_utc) "
        "VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::format("prepare account event insert: {}", sqlite3_errmsg(db)));
    }
    bind_text(stmt, 1, str_or_empty(event, "eventId"));
    bind_text(stmt, 2, str_or_empty(event, "eventType"));
    bind_text(stmt, 3, str_or_empty(event, "action"));
    bind_text(stmt, 4, str_or_empty(event, "aggregateId"));
    bind_text(stmt, 5, str_or_empty(event, "occurredUtc"));
    bind_text(stmt, 6, event.dump());
    const int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::format("insert account event: {}", sqlite3_errmsg(db)));
    }
}

bool event_was_inserted(sqlite3* db) {
    return sqlite3_changes(db) > 0;
}

void upsert_user(sqlite3* db, const nlohmann::json& user, const nlohmann::json& event) {
    sqlite3_stmt* stmt = nullptr;
    static const char* const sql =
        "INSERT INTO users "
        "(id, user_name, email, first_name, last_name, country, postal, auth_type, provider, updated_utc) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "user_name=excluded.user_name, email=excluded.email, first_name=excluded.first_name, "
        "last_name=excluded.last_name, country=excluded.country, postal=excluded.postal, "
        "auth_type=excluded.auth_type, provider=excluded.provider, updated_utc=excluded.updated_utc";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::format("prepare user upsert: {}", sqlite3_errmsg(db)));
    }
    bind_text(stmt, 1, str_or_empty(user, "id"));
    bind_text(stmt, 2, str_or_empty(user, "userName"));
    bind_text(stmt, 3, str_or_empty(user, "email"));
    bind_text(stmt, 4, str_or_empty(user, "firstName"));
    bind_text(stmt, 5, str_or_empty(user, "lastName"));
    bind_text(stmt, 6, str_or_empty(user, "country"));
    bind_text(stmt, 7, str_or_empty(user, "postal"));
    bind_text(stmt, 8, str_or_empty(user, "authType"));
    bind_text(stmt, 9, str_or_empty(user, "provider"));
    bind_text(stmt, 10, str_or_empty(event, "occurredUtc"));
    const int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::format("upsert user: {}", sqlite3_errmsg(db)));
    }
}

int int_or_zero(const nlohmann::json& obj, const char* key) {
    if (!obj.is_object() || !obj.contains(key) || obj[key].is_null()) return 0;
    if (obj[key].is_number_integer()) return obj[key].get<int>();
    if (obj[key].is_string()) {
        try { return std::stoi(obj[key].get<std::string>()); } catch (...) { return 0; }
    }
    return 0;
}

// 64-bit variant, required for dbo.Users.UsersId: it is a `bigint identity(1,128)` on a
// peer-to-peer replicated database, so nodes are seeded into separate ranges and the value routinely
// exceeds 32 bits. Reading it as an int truncates to the low 32 bits, which stores a DIFFERENT id
// rather than an approximate one (covered by preserves_users_id_beyond_32_bits).
std::int64_t int64_or_zero(const nlohmann::json& obj, const char* key) {
    if (!obj.is_object() || !obj.contains(key) || obj[key].is_null()) return 0;
    if (obj[key].is_number_integer()) return obj[key].get<std::int64_t>();
    if (obj[key].is_string()) {
        try { return std::stoll(obj[key].get<std::string>()); } catch (...) { return 0; }
    }
    return 0;
}

// Full dbo.Users row mirror (id, UsersId, userName, email, lastVisit, access, suspended, authType,
// deleted, deletedUtc, prime, prime_expired) fed by the fishfind-frontend outbox dispatcher
// (Run-UsersSyncDispatch.ps1), which snapshots EVERY write to dbo.Users -- including a manual admin
// UPDATE to access/suspended/deleted, not just app code paths. Distinct from `users` above, which only
// ever carries the narrower registration/OAuth profile fields.
//
// prime is 0 on the 'created' event of a new account and arrives for real on the following 'updated'
// event, because the frontend writes the Users row before dbo.sp_user_prime_assign issues its prime
// (envfish-db/CLAUDE.md -> "Per-user prime allocation"). 0 therefore means "not allocated yet" here
// exactly as it does in dbo.Users -- it is NOT a parse failure, and it is not a state to alarm on
// until the second event fails to show up.
void upsert_user_sync(sqlite3* db, const nlohmann::json& user, const nlohmann::json& event) {
    sqlite3_stmt* stmt = nullptr;
    static const char* const sql =
        "INSERT INTO users_sync "
        "(id, users_id, user_name, email, last_visit, access, suspended, auth_type, deleted, deleted_utc, "
        "prime, prime_expired, updated_utc) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "users_id=excluded.users_id, user_name=excluded.user_name, email=excluded.email, "
        "last_visit=excluded.last_visit, access=excluded.access, suspended=excluded.suspended, "
        "auth_type=excluded.auth_type, deleted=excluded.deleted, deleted_utc=excluded.deleted_utc, "
        "prime=excluded.prime, prime_expired=excluded.prime_expired, "
        "updated_utc=excluded.updated_utc";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::format("prepare users_sync upsert: {}", sqlite3_errmsg(db)));
    }
    bind_text(stmt, 1, str_or_empty(user, "id"));
    sqlite3_bind_int64(stmt, 2, int64_or_zero(user, "usersId"));
    bind_text(stmt, 3, str_or_empty(user, "userName"));
    bind_text(stmt, 4, str_or_empty(user, "email"));
    bind_text(stmt, 5, str_or_empty(user, "lastVisit"));
    sqlite3_bind_int(stmt, 6, int_or_zero(user, "access"));
    sqlite3_bind_int(stmt, 7, bool_or_zero(user, "suspended"));
    bind_text(stmt, 8, str_or_empty(user, "authType"));
    sqlite3_bind_int(stmt, 9, bool_or_zero(user, "deleted"));
    const std::string deleted_utc = str_or_empty(user, "deletedUtc");
    if (deleted_utc.empty()) {
        sqlite3_bind_null(stmt, 10);
    } else {
        bind_text(stmt, 10, deleted_utc);
    }
    // bigint, same 64-bit reasoning as users_id: the global prime sequence starts above 10^6 and only
    // grows, so a 32-bit bind would eventually store a different prime rather than a close one.
    sqlite3_bind_int64(stmt, 11, int64_or_zero(user, "prime"));
    // A calendar date ("yyyy-MM-dd"), stored verbatim. NULL only on events replayed from outbox rows
    // written before the column existed.
    const std::string prime_expired = str_or_empty(user, "primeExpired");
    if (prime_expired.empty()) {
        sqlite3_bind_null(stmt, 12);
    } else {
        bind_text(stmt, 12, prime_expired);
    }
    bind_text(stmt, 13, str_or_empty(event, "occurredUtc"));
    const int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::format("upsert users_sync: {}", sqlite3_errmsg(db)));
    }
}

void upsert_api_key(sqlite3* db, const nlohmann::json& key, const nlohmann::json& event) {
    const std::string action = str_or_empty(event, "action");
    sqlite3_stmt* stmt = nullptr;
    static const char* const sql =
        "INSERT INTO user_api_key "
        "(key_id, user_id, api_key, created_utc, expires_utc, disabled_utc, deleted_utc, updated_utc) "
        "VALUES (?, ?, ?, ?, ?, CASE WHEN ? THEN ? ELSE NULL END, CASE WHEN ? THEN ? ELSE NULL END, ?) "
        "ON CONFLICT(key_id) DO UPDATE SET "
        "user_id=COALESCE(NULLIF(excluded.user_id,''), user_api_key.user_id), "
        "api_key=COALESCE(NULLIF(excluded.api_key,''), user_api_key.api_key), "
        "created_utc=COALESCE(NULLIF(excluded.created_utc,''), user_api_key.created_utc), "
        "expires_utc=COALESCE(NULLIF(excluded.expires_utc,''), user_api_key.expires_utc), "
        "disabled_utc=CASE WHEN ? THEN ? WHEN ? THEN NULL ELSE user_api_key.disabled_utc END, "
        "deleted_utc=CASE WHEN ? THEN ? ELSE user_api_key.deleted_utc END, "
        "updated_utc=excluded.updated_utc";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::format("prepare api key upsert: {}", sqlite3_errmsg(db)));
    }

    const bool is_disabled = bool_or_zero(key, "isDisabled") != 0;
    const bool is_delete = action == "deleted";
    const bool is_enable = action == "enabled" || (action == "disabled" && !is_disabled);
    const std::string now = str_or_empty(event, "occurredUtc");

    bind_text(stmt, 1, str_or_empty(key, "keyId"));
    bind_text(stmt, 2, str_or_empty(key, "userId"));
    bind_text(stmt, 3, str_or_empty(key, "apiKey"));
    bind_text(stmt, 4, str_or_empty(key, "createdUtc"));
    bind_text(stmt, 5, str_or_empty(key, "expiresUtc"));
    sqlite3_bind_int(stmt, 6, is_disabled ? 1 : 0);
    bind_text(stmt, 7, now);
    sqlite3_bind_int(stmt, 8, is_delete ? 1 : 0);
    bind_text(stmt, 9, now);
    bind_text(stmt, 10, now);
    sqlite3_bind_int(stmt, 11, is_disabled ? 1 : 0);
    bind_text(stmt, 12, now);
    sqlite3_bind_int(stmt, 13, is_enable ? 1 : 0);
    sqlite3_bind_int(stmt, 14, is_delete ? 1 : 0);
    bind_text(stmt, 15, now);

    const int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::format("upsert api key: {}", sqlite3_errmsg(db)));
    }
}

}  // namespace

AccountMirrorStore::AccountMirrorStore(std::string db_path) : db_path_(std::move(db_path)) {}

void AccountMirrorStore::ensure_schema() {
    SqliteDb handle;
    if (sqlite3_open_v2(db_path_.c_str(), &handle.db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        const std::string msg = handle.db != nullptr ? sqlite3_errmsg(handle.db) : "unknown error";
        throw std::runtime_error(std::format("failed to open account mirror database '{}': {}", db_path_, msg));
    }

    static const char* const ddl =
        "PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS account_events ("
        "  event_id TEXT PRIMARY KEY,"
        "  event_type TEXT NOT NULL,"
        "  action TEXT NOT NULL,"
        "  aggregate_id TEXT NOT NULL,"
        "  occurred_utc TEXT NOT NULL,"
        "  payload_json TEXT NOT NULL,"
        "  received_utc TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS users ("
        "  id TEXT PRIMARY KEY,"
        "  user_name TEXT NOT NULL DEFAULT '',"
        "  email TEXT NOT NULL DEFAULT '',"
        "  first_name TEXT NOT NULL DEFAULT '',"
        "  last_name TEXT NOT NULL DEFAULT '',"
        "  country TEXT NOT NULL DEFAULT '',"
        "  postal TEXT NOT NULL DEFAULT '',"
        "  auth_type TEXT NOT NULL DEFAULT '',"
        "  provider TEXT NOT NULL DEFAULT '',"
        "  updated_utc TEXT NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);"
        "CREATE TABLE IF NOT EXISTS users_sync ("
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
        "  prime INTEGER NOT NULL DEFAULT 0,"
        "  prime_expired TEXT NULL,"
        "  updated_utc TEXT NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS ix_users_sync_email ON users_sync(email);"
        "CREATE TABLE IF NOT EXISTS user_api_key ("
        "  key_id TEXT PRIMARY KEY,"
        "  user_id TEXT NOT NULL DEFAULT '',"
        "  api_key TEXT NOT NULL DEFAULT '',"
        "  created_utc TEXT NOT NULL DEFAULT '',"
        "  expires_utc TEXT NOT NULL DEFAULT '',"
        "  disabled_utc TEXT NULL,"
        "  deleted_utc TEXT NULL,"
        "  updated_utc TEXT NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS ix_user_api_key_user ON user_api_key(user_id, created_utc DESC);"
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_user_api_key_secret ON user_api_key(api_key) WHERE api_key <> '';";
    exec(handle.db, ddl, "create account mirror schema");

    // Migrations for mirror databases created before a column existed (see add_column_if_missing).
    // dbo.Users.prime is a bigint -- SQLite INTEGER is 64-bit, so it holds the full range.
    add_column_if_missing(handle.db, "users_sync", "prime", "INTEGER NOT NULL DEFAULT 0");
    add_column_if_missing(handle.db, "users_sync", "prime_expired", "TEXT NULL");
}

bool AccountMirrorStore::apply_event(const nlohmann::json& event) {
    const std::string event_id = str_or_empty(event, "eventId");
    if (event_id.empty()) {
        throw std::runtime_error("account event missing eventId");
    }

    SqliteDb handle;
    if (sqlite3_open_v2(db_path_.c_str(), &handle.db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        const std::string msg = handle.db != nullptr ? sqlite3_errmsg(handle.db) : "unknown error";
        throw std::runtime_error(std::format("failed to open account mirror database '{}': {}", db_path_, msg));
    }

    Tx tx(handle.db);
    mark_event(handle.db, event);
    if (!event_was_inserted(handle.db)) {
        tx.commit();
        return false;
    }

    const std::string type = str_or_empty(event, "eventType");
    if (type == "fishfind.account.user") {
        upsert_user(handle.db, event.contains("user") ? event["user"] : nlohmann::json::object(), event);
    } else if (type == "fishfind.account.api_key") {
        upsert_api_key(handle.db, event.contains("apiKey") ? event["apiKey"] : nlohmann::json::object(), event);
    } else if (type == "fishfind.account.user_sync") {
        upsert_user_sync(handle.db, event.contains("user") ? event["user"] : nlohmann::json::object(), event);
    }
    tx.commit();
    return true;
}

}  // namespace cproxy
