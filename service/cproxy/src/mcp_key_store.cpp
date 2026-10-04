#include "mcp_key_store.hpp"

#include <openssl/evp.h>
#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <format>
#include <stdexcept>
#include <system_error>

#include "log.hpp"

namespace cproxy {

namespace {

/** Longest token worth hashing. Real tokens are ~50 chars; anything huge is junk, not a key. */
constexpr std::size_t kMaxTokenLength = 512;

struct SqliteDb {
    sqlite3* db = nullptr;
    ~SqliteDb() {
        if (db != nullptr) sqlite3_close(db);
    }
};

std::string column_text(sqlite3_stmt* stmt, int col) {
    const unsigned char* text = sqlite3_column_text(stmt, col);
    return text != nullptr ? reinterpret_cast<const char*>(text) : "";
}

bool is_lower_hex64(const std::string& s) {
    return s.size() == 64 && std::all_of(s.begin(), s.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

/** "YYYY-MM-DD" -> that UTC day; nullopt for anything else, including an impossible date. */
std::optional<std::chrono::sys_days> parse_day(const std::string& s) {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-') return std::nullopt;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (i == 4 || i == 7) continue;
        if (s[i] < '0' || s[i] > '9') return std::nullopt;
    }
    const std::chrono::year_month_day ymd{std::chrono::year{std::stoi(s.substr(0, 4))},
                                          std::chrono::month{static_cast<unsigned>(std::stoi(s.substr(5, 2)))},
                                          std::chrono::day{static_cast<unsigned>(std::stoi(s.substr(8, 2)))}};
    if (!ymd.ok()) return std::nullopt;
    return std::chrono::sys_days{ymd};
}

/** Reads the whole active key set. Throws std::runtime_error on any structural problem. */
std::shared_ptr<const std::unordered_map<std::string, McpKey>> load_keys(const std::string& path) {
    SqliteDb handle;
    if (sqlite3_open_v2(path.c_str(), &handle.db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        const std::string msg = handle.db != nullptr ? sqlite3_errmsg(handle.db) : "unknown error";
        throw std::runtime_error(std::format("failed to open MCP key database '{}': {}", path, msg));
    }
    sqlite3_stmt* stmt = nullptr;
    static const char* const sql =
        "SELECT key_id, token_sha256, label, expires_utc, disabled FROM mcp_keys";
    if (sqlite3_prepare_v2(handle.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::format(
            "failed to query MCP key database '{}': {} — expected mcp_keys(key_id, token_sha256, "
            "label, created_utc, expires_utc, disabled)",
            path, sqlite3_errmsg(handle.db)));
    }

    auto keys = std::make_shared<std::unordered_map<std::string, McpKey>>();
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        McpKey key;
        key.admin = true;  // hand-made keys are the operator's own (see McpKey::admin)
        key.key_id = column_text(stmt, 0);
        std::string hash = column_text(stmt, 1);
        std::transform(hash.begin(), hash.end(), hash.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        key.label = column_text(stmt, 2);
        const bool has_expiry = sqlite3_column_type(stmt, 3) != SQLITE_NULL;
        const std::string expires = column_text(stmt, 3);
        const bool disabled = sqlite3_column_int(stmt, 4) != 0;

        if (key.key_id.empty() || !is_lower_hex64(hash)) {
            sqlite3_finalize(stmt);
            throw std::runtime_error(std::format(
                "MCP key database '{}' has a malformed row (key_id must be non-empty and "
                "token_sha256 64 hex characters)",
                path));
        }
        if (has_expiry && !expires.empty()) {
            key.expires = parse_day(expires);
            if (!key.expires) {
                sqlite3_finalize(stmt);
                throw std::runtime_error(std::format(
                    "MCP key database '{}': key '{}' has expires_utc '{}', expected YYYY-MM-DD or NULL",
                    path, key.key_id, expires));
            }
        }
        if (!disabled) keys->emplace(hash, std::move(key));
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::format("MCP key database '{}' query did not complete cleanly", path));
    }
    return keys;
}

}  // namespace

std::string sha256_hex(const std::string& data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("SHA-256 failed");
    }
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i) out += std::format("{:02x}", md[i]);
    return out;
}

McpKeyStore::McpKeyStore(std::string db_path, int reload_seconds)
    : path_(std::move(db_path)), reload_interval_(std::max(0, reload_seconds)) {
    keys_ = load_keys(path_);
    std::error_code ec;
    loaded_mtime_ = std::filesystem::last_write_time(path_, ec);
    last_check_ = std::chrono::steady_clock::now();
}

void McpKeyStore::maybe_reload(std::chrono::steady_clock::time_point now) {
    // Called with mu_ held.
    if (now - last_check_ < reload_interval_) return;
    last_check_ = now;
    std::error_code ec;
    const auto mtime = std::filesystem::last_write_time(path_, ec);
    if (ec) {
        // The file vanished: keep the last good set, say why. Same stance as a bad replacement.
        if (last_error_.empty()) {
            last_error_ = std::format("MCP key database '{}' is unreadable: {}", path_, ec.message());
            log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"ERROR\",\"msg\":\"{}; keeping "
                                "the last loaded keys\"}}",
                                last_error_));
        }
        return;
    }
    if (mtime == loaded_mtime_) return;
    try {
        keys_ = load_keys(path_);
        loaded_mtime_ = mtime;
        last_error_.clear();
        log_raw(std::format("{{\"service\":\"cproxy\",\"msg\":\"MCP key store reloaded\",\"keys\":{}}}",
                            keys_->size()));
    } catch (const std::exception& ex) {
        // Remember the mtime so a broken file is reported once, not on every request.
        loaded_mtime_ = mtime;
        last_error_ = ex.what();
        log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"ERROR\",\"msg\":\"MCP key store "
                            "reload failed, keeping the last loaded keys: {}\"}}",
                            last_error_));
    }
}

std::optional<McpKey> McpKeyStore::find(const std::string& token,
                                        std::chrono::system_clock::time_point now) {
    if (token.empty() || token.size() > kMaxTokenLength) return std::nullopt;
    const std::string hash = sha256_hex(token);
    std::shared_ptr<const Map> keys;
    {
        std::lock_guard<std::mutex> lock(mu_);
        maybe_reload(std::chrono::steady_clock::now());
        keys = keys_;
    }
    const auto it = keys->find(hash);
    if (it == keys->end()) return std::nullopt;
    if (it->second.expires && std::chrono::floor<std::chrono::days>(now) > *it->second.expires) {
        return std::nullopt;
    }
    return it->second;
}

std::size_t McpKeyStore::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return keys_->size();
}

std::string McpKeyStore::last_error() const {
    std::lock_guard<std::mutex> lock(mu_);
    return last_error_;
}

}  // namespace cproxy
