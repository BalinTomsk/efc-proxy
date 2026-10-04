#include "user_mcp_key_store.hpp"

#include <sqlite3.h>

#include <format>
#include <utility>

namespace cproxy {
namespace {

constexpr const char* kTokenPrefix = "ffmcp_";

struct SqliteDb {
    sqlite3* db = nullptr;
    ~SqliteDb() {
        if (db != nullptr) sqlite3_close(db);
    }
};

}  // namespace

UserMcpKeyStore::UserMcpKeyStore(std::string mirror_db_path) : path_(std::move(mirror_db_path)) {}

std::optional<McpKey> UserMcpKeyStore::find(const std::string& token) const {
    if (path_.empty() || token.rfind(kTokenPrefix, 0) != 0) return std::nullopt;

    std::string error;
    std::optional<McpKey> found;

    SqliteDb handle;
    if (sqlite3_open_v2(path_.c_str(), &handle.db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        error = std::format("failed to open account mirror '{}': {}", path_,
                            handle.db != nullptr ? sqlite3_errmsg(handle.db) : "unknown error");
    } else {
        // users_sync.id and user_mcp_key.user_id both come from a .NET Guid.ToString(), but through
        // two different producers (the users-sync dispatcher and the Profile page); NOCASE keeps a
        // future change of either one's GUID casing from silently refusing every key.
        static const char* const sql =
            "SELECT k.key_id, s.access FROM user_mcp_key k "
            "JOIN users_sync s ON s.id = k.user_id COLLATE NOCASE "
            "WHERE k.token_sha256 = ? AND k.revoked_utc IS NULL "
            "  AND datetime(substr(k.created_utc, 1, 19)) > datetime('now', '-7 days') "
            "  AND s.deleted = 0 AND s.suspended = 0 "
            "LIMIT 1";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(handle.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            error = std::format("failed to query user mcp keys in '{}': {}", path_, sqlite3_errmsg(handle.db));
        } else {
            const std::string digest = sha256_hex(token);
            sqlite3_bind_text(stmt, 1, digest.c_str(), -1, SQLITE_TRANSIENT);
            const int rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                const auto* id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                const std::string key_id = std::string("user:") + (id != nullptr ? id : "");
                // The owner's privilege is read on every lookup, so a demotion takes effect on the next
                // request, like a suspension does.
                const bool admin = sqlite3_column_int(stmt, 1) == 255;
                found = McpKey{key_id, key_id, std::nullopt, admin};
            } else if (rc != SQLITE_DONE) {
                error = std::format("user mcp key lookup in '{}' failed: {}", path_, sqlite3_errmsg(handle.db));
            }
            sqlite3_finalize(stmt);
        }
    }

    std::lock_guard<std::mutex> lock(mu_);
    last_error_ = error;
    return found;
}

std::string UserMcpKeyStore::last_error() const {
    std::lock_guard<std::mutex> lock(mu_);
    return last_error_;
}

}  // namespace cproxy
