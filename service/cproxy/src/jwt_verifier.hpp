#pragma once

#include <chrono>
#include <string>

namespace cproxy {

/**
 * The claim set the frontend mints for a gated call, matching `fishfind-frontend/doc/envfish-jwt.html`:
 *
 *   { "iss":"envfish", "iat":…, "exp":<end of the current UTC day>, "aud":"fishfind.info",
 *     "sub":"cproxy", "server":"<dbo.day_keys.guid for today>",
 *     "user":"<Users.prime * Users_Prime.prime for today>" }
 *
 * `server` carries exactly the credential the `X-Day-Guid` header used to carry, so the day-key store
 * stays the authority on it; `user` is the per-account product cproxy re-derives from its own mirror
 * (see UserPrimeStore). Both are kept as strings: `user` is a product of two bigints and overflows
 * double, so a JSON number would be silently rounded by any parser that reads it as one.
 */
struct JwtClaims {
    std::string issuer;    // iss
    std::string audience;  // aud
    std::string subject;   // sub
    std::string server;    // day-key GUID
    std::string user;      // decimal product, empty when the caller is not a registered user
    long long issued_at = 0;
    long long expires_at = 0;
    // `adm` — true only in a token the portal minted for one of its configured admin accounts
    // (Profile -> Gateway token). It grants nothing extra on the proxy surface; its ONE use is
    // permission to correct this process's clock offset (see ClockOffset and check_gate_credential).
    // Trustworthy for the same reason `server` is: it is inside the HMAC, so forging it needs the
    // signing secret.
    bool admin = false;
};

/**
 * What the token must say to be accepted. An empty `issuer`/`audience`/`subject` means "do not check
 * this claim"; `secret` empty means JWT verification is not configured at all and nothing here runs.
 */
struct JwtVerifyOptions {
    std::string secret;
    std::string issuer;
    std::string audience;
    std::string subject;
    // Clock skew allowance on exp/iat, in seconds. The frontend and the proxy are different hosts
    // with independent clocks and the token's whole lifetime is one day, so a few minutes of slack
    // costs nothing and removes a class of "works until it doesn't" failures.
    int leeway_seconds = 300;
};

struct JwtResult {
    bool ok = false;
    /** Why it failed, for the LOG only — the caller answers a generic 500 either way. */
    std::string error;
    JwtClaims claims;

    /**
     * The MAC verified, so `claims` came from the holder of the signing secret and may be READ even
     * when `ok` is false. It is still not a pass — `ok` is the only thing that clears the gate.
     */
    bool signature_ok = false;
    /**
     * Set when `signature_ok` is true, every non-time claim matched, and the ONLY thing wrong was
     * `exp`/`nbf`/`iat` — i.e. an authentic token that this host's clock disagrees with.
     *
     * This distinction is what makes clock alignment able to fire when it is actually needed. Skew
     * larger than the leeway rejects the very tokens that could report it, so without separating
     * "authentic but out of time range" from "forged", the correction could only ever run while the
     * clocks were already close enough not to need it.
     */
    bool time_rejected = false;
};

/**
 * Parses and verifies a compact JWS with **HS512 and nothing else**.
 *
 * The algorithm is pinned rather than read from the header on purpose: honouring the header's `alg`
 * is the classic JWT forgery hole ("alg":"none" is accepted outright, and an RS256 verifier fed an
 * HS256 token will happily HMAC with the public key). This function rejects any token whose header
 * does not say HS512, so there is nothing for an attacker to downgrade to.
 *
 * `exp` is REQUIRED — a token that never expires would reintroduce exactly the "leaked credential
 * stays valid forever" problem the day-key rotation exists to avoid. `iat`, when present, may not be
 * in the future beyond the leeway.
 *
 * Never throws: a malformed token is an ordinary `ok = false` with a reason in `error`.
 */
JwtResult verify_hs512(const std::string& token, const JwtVerifyOptions& opts,
                       std::chrono::system_clock::time_point now);

/**
 * The token out of an `Authorization: Bearer <token>` header value; empty for an absent header, a
 * different scheme, or a missing token. The scheme is matched case-insensitively (RFC 7235 §2.1).
 */
std::string bearer_token(const std::string& authorization_header);

/** base64url (RFC 4648 §5, padding optional) -> bytes. Returns false on any character outside the
 *  alphabet or a length that cannot be a base64 group. Exposed for tests. */
bool base64url_decode(const std::string& input, std::string& out);

}  // namespace cproxy
