#pragma once

#include <map>
#include <string>

#include "config.hpp"

namespace cproxy {

/**
 * Reads a dotenv file (`KEY=VALUE` per line; blank lines and `#` comments ignored) and returns the
 * entries, with any `enc:v1:` value decrypted via {@link decrypt_if_needed}. A missing file yields an
 * empty map (dotenv is optional); a present-but-encrypted value with no master key is a hard error.
 *
 * The value is taken verbatim after the first `=` (matching `Protect-Env.ps1`), so values must not
 * carry inline `# comments`.
 *
 * @param path dotenv file path (empty => no file, empty map)
 */
std::map<std::string, std::string> load_dotenv(const std::string& path);

/**
 * Builds an {@link EnvLookup} where a real process environment variable always wins, falling back to
 * the dotenv map — matching the platform rule that real env / JVM props override `.env`.
 */
EnvLookup make_env_lookup(const std::map<std::string, std::string>& dotenv);

}  // namespace cproxy
