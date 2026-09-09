#include "jwt_verifier.hpp"

#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <format>
#include <vector>

#include <nlohmann/json.hpp>

namespace cproxy {

namespace {

/** Reverse base64url alphabet; 0xFF marks a character that is not in it. */
const std::array<unsigned char, 256>& b64url_table() {
    static const std::array<unsigned char, 256> table = [] {
        std::array<unsigned char, 256> t{};
        t.fill(0xFF);
        const std::string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (std::size_t i = 0; i < alphabet.size(); ++i) {
            t[static_cast<unsigned char>(alphabet[i])] = static_cast<unsigned char>(i);
        }
        return t;
    }();
    return table;
}

std::string hmac_sha512(const std::string& key, const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    // An empty key would make HMAC() take the nullptr branch on some builds; the caller never passes
    // one (jwt_enabled() is false without a secret), but be explicit rather than rely on that.
    const unsigned char* key_bytes = reinterpret_cast<const unsigned char*>(key.data());
    if (HMAC(EVP_sha512(), key_bytes, static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest,
             &length) == nullptr) {
        return {};
    }
    return std::string(reinterpret_cast<char*>(digest), length);
}

/** A claim that may legitimately arrive as either a JSON string or a JSON number, rendered as text.
 *  `user` is minted as a string (see JwtClaims) but reading a number too costs one branch and makes
 *  the verifier tolerant of a hand-built token. */
std::string claim_as_string(const nlohmann::json& obj, const char* key) {
    if (!obj.is_object() || !obj.contains(key) || obj[key].is_null()) return {};
    const auto& v = obj[key];
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number_integer()) return std::to_string(v.get<std::int64_t>());
    if (v.is_number_unsigned()) return std::to_string(v.get<std::uint64_t>());
    return {};
}

long long claim_as_int(const nlohmann::json& obj, const char* key, bool& present) {
    present = false;
    if (!obj.is_object() || !obj.contains(key) || obj[key].is_null()) return 0;
    const auto& v = obj[key];
    if (v.is_number_integer() || v.is_number_unsigned()) {
        present = true;
        return v.get<long long>();
    }
    if (v.is_number_float()) {  // NumericDate is defined as a number, not necessarily an integer
        present = true;
        return static_cast<long long>(v.get<double>());
    }
    if (v.is_string()) {
        try {
            const long long parsed = std::stoll(v.get<std::string>());
            present = true;
            return parsed;
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

/**
 * True when `expected` is what the token says. `aud` is allowed to be an array, which RFC 7519 §4.1.3
 * permits and some minters emit; a single string is the shape this platform produces.
 */
bool audience_matches(const nlohmann::json& payload, const std::string& expected) {
    if (expected.empty()) return true;
    if (!payload.contains("aud")) return false;
    const auto& aud = payload["aud"];
    if (aud.is_string()) return aud.get<std::string>() == expected;
    if (aud.is_array()) {
        for (const auto& entry : aud) {
            if (entry.is_string() && entry.get<std::string>() == expected) return true;
        }
    }
    return false;
}

}  // namespace

bool base64url_decode(const std::string& input, std::string& out) {
    out.clear();
    const auto& table = b64url_table();

    std::uint32_t accumulator = 0;
    int bits = 0;
    std::size_t symbols = 0;
    for (const char c : input) {
        if (c == '=') break;  // padding is optional in base64url; anything after it is padding too
        const unsigned char decoded = table[static_cast<unsigned char>(c)];
        if (decoded == 0xFF) return false;
        accumulator = (accumulator << 6) | decoded;
        bits += 6;
        ++symbols;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((accumulator >> bits) & 0xFF));
        }
    }
    // 1 leftover symbol carries 6 bits, which cannot be a byte — that length is always corruption.
    return (symbols % 4) != 1;
}

std::string bearer_token(const std::string& authorization_header) {
    static const std::string scheme = "bearer";
    std::size_t i = authorization_header.find_first_not_of(" \t");
    if (i == std::string::npos) return {};
    if (authorization_header.size() - i < scheme.size() + 1) return {};

    for (std::size_t k = 0; k < scheme.size(); ++k) {
        if (std::tolower(static_cast<unsigned char>(authorization_header[i + k])) != scheme[k]) {
            return {};
        }
    }
    std::size_t j = i + scheme.size();
    if (authorization_header[j] != ' ' && authorization_header[j] != '\t') return {};

    j = authorization_header.find_first_not_of(" \t", j);
    if (j == std::string::npos) return {};
    std::size_t end = authorization_header.find_last_not_of(" \t\r\n");
    return authorization_header.substr(j, end - j + 1);
}

JwtResult verify_hs512(const std::string& token, const JwtVerifyOptions& opts,
                       std::chrono::system_clock::time_point now) {
    JwtResult result;
    if (opts.secret.empty()) {
        result.error = "no signing secret configured";
        return result;
    }
    if (token.empty()) {
        result.error = "empty token";
        return result;
    }

    const std::size_t first_dot = token.find('.');
    if (first_dot == std::string::npos) {
        result.error = "not a compact JWS";
        return result;
    }
    const std::size_t second_dot = token.find('.', first_dot + 1);
    if (second_dot == std::string::npos || token.find('.', second_dot + 1) != std::string::npos) {
        result.error = "not a compact JWS";
        return result;
    }

    const std::string signing_input = token.substr(0, second_dot);
    std::string header_bytes;
    std::string payload_bytes;
    std::string signature;
    if (!base64url_decode(token.substr(0, first_dot), header_bytes) ||
        !base64url_decode(token.substr(first_dot + 1, second_dot - first_dot - 1), payload_bytes) ||
        !base64url_decode(token.substr(second_dot + 1), signature)) {
        result.error = "base64url decode failed";
        return result;
    }

    nlohmann::json header = nlohmann::json::parse(header_bytes, nullptr, false);
    if (header.is_discarded() || !header.is_object()) {
        result.error = "header is not JSON";
        return result;
    }
    // Pinned, not read-and-obeyed. See the header comment: trusting `alg` is how "none" tokens and
    // algorithm-confusion forgeries get in.
    if (claim_as_string(header, "alg") != "HS512") {
        result.error = "unsupported alg (only HS512 is accepted)";
        return result;
    }
    // A `crit` header names extensions the verifier MUST understand (RFC 7515 §4.1.11). We understand
    // none, so any token carrying it is refused rather than silently ignored.
    if (header.contains("crit")) {
        result.error = "unsupported crit header";
        return result;
    }

    // Verify BEFORE looking at any claim: the payload is attacker-supplied until the MAC says
    // otherwise, and CRYPTO_memcmp keeps the comparison length-safe and constant-time.
    const std::string expected = hmac_sha512(opts.secret, signing_input);
    if (expected.empty()) {
        result.error = "HMAC computation failed";
        return result;
    }
    if (signature.size() != expected.size() ||
        CRYPTO_memcmp(signature.data(), expected.data(), expected.size()) != 0) {
        result.error = "signature mismatch";
        return result;
    }

    nlohmann::json payload = nlohmann::json::parse(payload_bytes, nullptr, false);
    if (payload.is_discarded() || !payload.is_object()) {
        result.error = "payload is not JSON";
        return result;
    }

    const long long epoch_now =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    bool has_exp = false;
    const long long exp = claim_as_int(payload, "exp", has_exp);
    if (!has_exp) {
        result.error = "missing exp";
        return result;
    }
    if (epoch_now > exp + opts.leeway_seconds) {
        result.error = "token expired";
        return result;
    }

    bool has_nbf = false;
    const long long nbf = claim_as_int(payload, "nbf", has_nbf);
    if (has_nbf && epoch_now + opts.leeway_seconds < nbf) {
        result.error = "token not yet valid";
        return result;
    }

    bool has_iat = false;
    const long long iat = claim_as_int(payload, "iat", has_iat);
    if (has_iat && iat > epoch_now + opts.leeway_seconds) {
        result.error = "token issued in the future";
        return result;
    }

    if (!opts.issuer.empty() && claim_as_string(payload, "iss") != opts.issuer) {
        result.error = "issuer mismatch";
        return result;
    }
    if (!audience_matches(payload, opts.audience)) {
        result.error = "audience mismatch";
        return result;
    }
    if (!opts.subject.empty() && claim_as_string(payload, "sub") != opts.subject) {
        result.error = "subject mismatch";
        return result;
    }

    result.claims.issuer = claim_as_string(payload, "iss");
    result.claims.audience = payload.contains("aud") && payload["aud"].is_string()
                                 ? payload["aud"].get<std::string>()
                                 : opts.audience;
    result.claims.subject = claim_as_string(payload, "sub");
    result.claims.server = claim_as_string(payload, "server");
    result.claims.user = claim_as_string(payload, "user");
    result.claims.issued_at = iat;
    result.claims.expires_at = exp;
    result.ok = true;
    return result;
}

}  // namespace cproxy
