#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace cproxy {

/** One MCP client key, as identified to the logs. The secret itself is never held. */
struct McpKey {
    std::string key_id;
    std::string label;
    // Last valid UTC day, inclusive; nullopt = no expiry.
    std::optional<std::chrono::sys_days> expires;
    // 0.22.0: whether the caller is an admin, sent to docapi as X-Fish-Role "admin" (else "user"); docapi
    // shows fish information to admins only. A hand-made key (this store) is the operator's own and is
    // always admin; a self-service key is admin when its owning account is a superAdmin (access 255).
    bool admin = false;
};

/**
 * The credential for the MCP path (0.20.0): long-lived bearer keys, one per client, held as SHA-256
 * hashes in a small SQLite database on the volume:
 *
 *   mcp_keys(key_id TEXT PRIMARY KEY, token_sha256 TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
 *            created_utc TEXT NOT NULL, expires_utc TEXT NULL, disabled INTEGER NOT NULL DEFAULT 0)
 *
 * WHY NOT THE DAY-KEY JWT. That token expires at UTC midnight and is minted by the portal for a
 * signed-in session; an MCP client (Claude Code, Claude Desktop) is configured once with a header
 * and cannot renew anything. So the MCP path has its own credential, and only that path accepts it
 * — a key presented anywhere else is just an unverifiable Bearer token, i.e. a guest or a 500.
 *
 * WHY HASHES. The database is a deploy artifact copied around like the day-key file; holding only
 * SHA-256 of each token means a copy of it grants nothing. A token is 32 random bytes, so an
 * unsalted fast hash is the right tool (there is no low-entropy password to stretch).
 *
 * RELOADED, NOT LOAD-ONCE — unlike DayKeyStore. Revoking a key must not need a restart, so the
 * file's modification time is checked at most every `reload_seconds` (0 = on every lookup) and a
 * changed file is loaded again. A replacement that fails to load KEEPS THE LAST GOOD SET and is
 * reported by last_error(); refusing every MCP client because of a half-copied file is the worse
 * outage. Revoke by setting `disabled = 1` (or deleting the row) — not by corrupting the file.
 *
 * The bind mount must be the DIRECTORY holding the file, not the file itself: a single-file bind
 * mount pins the original inode, so a replaced file would never be seen inside the container.
 *
 * An empty table is a valid state (every key revoked) and refuses everything; a missing table,
 * a malformed hash, or an unparseable expiry is a load failure.
 */
class McpKeyStore {
public:
    /** Loads `db_path` read-only. Throws std::runtime_error if the first load fails. */
    McpKeyStore(std::string db_path, int reload_seconds);

    /**
     * The key `token` belongs to, if it is present, not disabled, and not past its expiry at `now`
     * (UTC). May reload the file first (see class comment). Thread-safe.
     */
    std::optional<McpKey> find(const std::string& token, std::chrono::system_clock::time_point now);

    /** Active (not disabled) keys in the current set. */
    std::size_t size() const;

    /** Why the most recent reload was rejected; empty after a successful one. */
    std::string last_error() const;

private:
    using Map = std::unordered_map<std::string, McpKey>;  // token_sha256 (lower hex) -> key

    void maybe_reload(std::chrono::steady_clock::time_point now);

    std::string path_;
    std::chrono::seconds reload_interval_;
    mutable std::mutex mu_;
    std::shared_ptr<const Map> keys_;
    std::filesystem::file_time_type loaded_mtime_{};
    std::chrono::steady_clock::time_point last_check_{};
    std::string last_error_;
};

/** Lower-case hex SHA-256 of `data`. Exposed for tests and the key generator's contract. */
std::string sha256_hex(const std::string& data);

}  // namespace cproxy
