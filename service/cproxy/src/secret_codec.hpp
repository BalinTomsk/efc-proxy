#pragma once

#include <string>

namespace cproxy {

/**
 * Unwraps individually-encrypted configuration values, byte-compatible with the platform's
 * `secret/Protect-Env.ps1` encryptor and the Java `SecretCodec` used by docapi/waterservice.
 *
 * A value may be stored as `enc:v1:<base64url(nonce || ciphertext || tag)>` instead of plaintext;
 * anything without that marker is returned untouched, so a partially-encrypted `.env` is valid.
 *
 * Algorithm: AES-256-GCM, 12-byte nonce, 128-bit tag, with the variable's own NAME bound in as
 * additional authenticated data (a ciphertext cannot be moved between variables). The 32-byte master
 * key comes from `FF_MASTER_KEY_FILE` (a path — preferred) or the raw `FF_MASTER_KEY`, decoded as hex
 * (64 chars) or base64, whitespace ignored.
 *
 * A missing/wrong key when an encrypted value is present is a HARD failure (throws), never a silent
 * pass-through — handing an `enc:v1:...` string downstream would surface as a baffling error later.
 */

/** True when the value carries the `enc:v1:` marker. */
bool is_encrypted(const std::string& value);

/**
 * Returns plaintext for a value: decrypts when it carries the `enc:v1:` marker, else returns it
 * verbatim. The master key is loaded once (lazily) and cached.
 *
 * @param name  variable name, bound in as AAD
 * @param value raw value from the dotenv file / environment
 * @throws std::runtime_error when encrypted but no usable key is configured, or the payload is
 *         malformed / tampered / from another key
 */
std::string decrypt_if_needed(const std::string& name, const std::string& value);

}  // namespace cproxy
