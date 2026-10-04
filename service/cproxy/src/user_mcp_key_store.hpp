#pragma once

#include <mutex>
#include <optional>
#include <string>

#include "mcp_key_store.hpp"

namespace cproxy {

/**
 * The second source of MCP keys (0.21.0): the ones registered users create for themselves on the
 * portal's Profile page, read out of cproxy's account mirror (AccountMirrorStore, table
 * `user_mcp_key`, fed by `account.mcp_key` events). The hand-made keys in McpKeyStore keep working;
 * the MCP path asks that store first and this one second.
 *
 * Same credential shape as McpKeyStore: an `ffmcp_` token of 32 random bytes, of which only the
 * lower-case hex SHA-256 is held anywhere -- the portal hashes it before it reaches SQL Server, the
 * event, or this mirror.
 *
 * A key is accepted when its hash is on file, it is not revoked, and the OWNING ACCOUNT is live
 * (`users_sync.deleted = 0 AND suspended = 0`). So suspending or deleting an account revokes all of
 * its keys with no extra step, as soon as the users-sync event lands.
 *
 * ONE INDEXED QUERY PER CALL, NO SNAPSHOT -- unlike UserPrimeStore. MCP traffic is small, and a
 * snapshot would let a revoked key keep working for its cache lifetime; here a revocation bites the
 * moment its event is applied. The mirror is opened read-only for each lookup, so a wrong path is an
 * error (every key refused), never a silently created empty file.
 *
 * Fails closed: a missing mirror, a missing table (a mirror that predates 0.21.0 until the consumer
 * runs ensure_schema), or any SQLite error yields nullopt and records last_error().
 */
class UserMcpKeyStore {
public:
    explicit UserMcpKeyStore(std::string mirror_db_path);

    /**
     * The key `token` belongs to, as `user:<key_id>` (so logs and the per-key rate limit never mix it
     * up with a hand-made key's id). nullopt for anything that is not a live key of a live account,
     * including a token without the `ffmcp_` prefix, which is refused without touching the mirror.
     * Thread-safe.
     */
    std::optional<McpKey> find(const std::string& token) const;

    /** Why the most recent lookup failed to run (not "key unknown"); empty after a clean one. */
    std::string last_error() const;

private:
    std::string path_;
    mutable std::mutex mu_;
    mutable std::string last_error_;
};

}  // namespace cproxy
