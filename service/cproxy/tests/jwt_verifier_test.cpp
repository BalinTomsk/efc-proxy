// Framework-free unit tests for the HS512 JWT verifier that replaced the raw X-Day-Guid header as
// the gateway credential (0.10.0). Registered with CTest; run via `ctest --test-dir build`.
//
// Every test passes an explicit `now`, so nothing here depends on the wall clock. The tokens are
// minted in-process by `mint` below rather than pasted in as fixtures: a fixture would have to carry
// a baked-in exp and would start failing on its own one day.
#include "check.hpp"

#include <openssl/hmac.h>

#include <chrono>
#include <iostream>
#include <string>

#include "jwt_verifier.hpp"

using namespace cproxy;

namespace {

const std::string kSecret = "a-test-signing-secret-that-is-comfortably-long-enough-for-hs512";

const std::string kB64UrlAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64url_encode(const std::string& bytes) {
    std::string out;
    int bits = 0;
    unsigned int accumulator = 0;
    for (unsigned char c : bytes) {
        accumulator = (accumulator << 8) | c;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(kB64UrlAlphabet[(accumulator >> bits) & 0x3F]);
        }
    }
    if (bits > 0) out.push_back(kB64UrlAlphabet[(accumulator << (6 - bits)) & 0x3F]);
    return out;  // unpadded, as RFC 7515 requires
}

/**
 * `encoded` with the final symbol of its last `.`-separated segment re-spelled: same significant
 * high bits, `low` OR-ed into the unused low bits (4 of them after a 2-symbol tail, 2 after a
 * 3-symbol one). The bytes a lenient decoder yields are unchanged; only the spelling differs.
 */
std::string respell_last_symbol(const std::string& encoded, unsigned low) {
    const std::size_t segment_at = encoded.rfind('.') + 1;  // npos + 1 == 0: no dot, whole string
    const std::size_t tail = (encoded.size() - segment_at) % 4;
    const unsigned unused_bits = tail == 2 ? 4 : tail == 3 ? 2 : 0;
    std::string out = encoded;
    const unsigned symbol = static_cast<unsigned>(kB64UrlAlphabet.find(out.back()));
    out.back() = kB64UrlAlphabet[symbol | (low & ((1u << unused_bits) - 1))];
    return out;
}

std::string hmac512(const std::string& key, const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest, &length);
    return std::string(reinterpret_cast<char*>(digest), length);
}

/** Mints a compact JWS from raw header/payload JSON, signing with `key`. */
std::string mint(const std::string& header_json, const std::string& payload_json,
                 const std::string& key = kSecret) {
    const std::string signing_input =
        base64url_encode(header_json) + "." + base64url_encode(payload_json);
    return signing_input + "." + base64url_encode(hmac512(key, signing_input));
}

/** The claim set the frontend actually sends (doc/envfish-jwt.html), parameterised for the tests. */
std::string platform_payload(long long exp, const std::string& server = "20C23A17-DEAD-BEEF",
                             const std::string& user = "2392473924723984",
                             const std::string& iss = "envfish",
                             const std::string& aud = "fishfind.info",
                             const std::string& sub = "cproxy") {
    return "{\"iss\":\"" + iss + "\",\"iat\":1788880000,\"exp\":" + std::to_string(exp) +
           ",\"aud\":\"" + aud + "\",\"sub\":\"" + sub + "\",\"server\":\"" + server +
           "\",\"user\":\"" + user + "\"}";
}

const std::string kHs512Header = "{\"typ\":\"JWT\",\"alg\":\"HS512\"}";

JwtVerifyOptions default_options() {
    JwtVerifyOptions opts;
    opts.secret = kSecret;
    opts.issuer = "envfish";
    opts.audience = "fishfind.info";
    opts.subject = "cproxy";
    return opts;
}

std::chrono::system_clock::time_point at_epoch(long long seconds) {
    return std::chrono::system_clock::time_point{std::chrono::seconds{seconds}};
}

void a_well_formed_platform_token_verifies_and_yields_both_claims() {
    const std::string token = mint(kHs512Header, platform_payload(1788900000));
    const JwtResult result = verify_hs512(token, default_options(), at_epoch(1788890000));

    CHECK(result.ok);
    CHECK(result.claims.server == "20C23A17-DEAD-BEEF");
    CHECK(result.claims.user == "2392473924723984");
    CHECK(result.claims.issuer == "envfish");
    CHECK(result.claims.subject == "cproxy");
    CHECK(result.claims.expires_at == 1788900000);
}

void a_token_minted_by_the_real_frontend_verifies() {
    // GOLDEN CROSS-LANGUAGE FIXTURE. Every other case here mints its token with `mint` above, which
    // means they all agree with THIS file's idea of the format and would keep passing even if the
    // two sides of the wire had drifted apart. This token was produced by the shipped C# minter —
    // FishTracker.FishApiJwt.Build, invoked by reflection on the built FishTracker.dll on
    // 2026-09-08 with the secret below — so it pins the actual contract: base64url without padding,
    // UTF-8 claim bytes, HMAC over the ASCII signing input, `user` as a string.
    //
    // `now` is passed explicitly, so the baked-in exp (end of that UTC day) never makes this expire.
    // If it starts failing, the frontend's serialisation changed and the wire format broke with it.
    const std::string minted_by_dotnet =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9."
        "eyJpc3MiOiJlbnZmaXNoIiwiaWF0IjoxNzg4ODg2ODUxLCJleHAiOjE3ODg5MTE5OTksImF1ZCI6ImZpc2hmaW5kLmlu"
        "Zm8iLCJzdWIiOiJjcHJveHkiLCJzZXJ2ZXIiOiIyMEMyM0ExNy04NDFELTQ0RTctQUQwRi1CMjZGQTZFODk2OEUiLCJ1"
        "c2VyIjoiMTA0NzI5MzE0MTg3In0."
        "rtjblzKLQvQrm0cG0F6MtuDtetE3TEdooQuJIy2zb2U-EB6vFi-3VTPvRRPyjRaQnFTJMJxUf51Klh5RW_Z6CA";

    const JwtResult result = verify_hs512(minted_by_dotnet, default_options(), at_epoch(1788900000));
    CHECK(result.ok);
    CHECK(result.claims.server == "20C23A17-841D-44E7-AD0F-B26FA6E8968E");
    CHECK(result.claims.user == "104729314187");  // 1000003 * 104729, as BigInteger produced it
    CHECK(result.claims.expires_at == 1788911999);

    // The frontend encodes canonically (Convert.ToBase64String zero-fills the unused bits), so the
    // spelling above is the only one of its 16 that may verify — see the respelling case below.
    CHECK(!verify_hs512(respell_last_symbol(minted_by_dotnet, 1), default_options(),
                        at_epoch(1788900000))
               .ok);
}

void a_token_signed_with_a_different_secret_is_rejected() {
    const std::string token = mint(kHs512Header, platform_payload(1788900000), "not-the-secret");
    CHECK(!verify_hs512(token, default_options(), at_epoch(1788890000)).ok);
}

void a_tampered_payload_is_rejected() {
    // Re-encode the payload with a different `user` but keep the original signature: this is the
    // whole attack the MAC exists to stop, and the one a "decode then trust" implementation misses.
    const std::string token = mint(kHs512Header, platform_payload(1788900000));
    const std::size_t first = token.find('.');
    const std::size_t second = token.find('.', first + 1);
    const std::string forged = token.substr(0, first + 1) +
                               base64url_encode(platform_payload(1788900000, "20C23A17-DEAD-BEEF",
                                                                 "999999999999")) +
                               token.substr(second);
    CHECK(!verify_hs512(forged, default_options(), at_epoch(1788890000)).ok);
}

void the_alg_none_forgery_is_rejected() {
    // The canonical JWT hole: a header claiming no signature is needed. The verifier pins HS512, so
    // there is nothing to downgrade to — with or without a signature segment.
    const std::string signing_input =
        base64url_encode("{\"typ\":\"JWT\",\"alg\":\"none\"}") + "." +
        base64url_encode(platform_payload(1788900000));
    CHECK(!verify_hs512(signing_input + ".", default_options(), at_epoch(1788890000)).ok);
    CHECK(!verify_hs512(mint("{\"typ\":\"JWT\",\"alg\":\"none\"}", platform_payload(1788900000)),
                        default_options(), at_epoch(1788890000))
               .ok);
}

void a_weaker_hmac_algorithm_is_rejected_before_the_signature_is_even_checked() {
    // A header claiming HS256, over a body signed with the real secret. The alg check runs first, so
    // the token is refused for what it claims to be rather than accepted because the bytes happen to
    // MAC correctly — that ordering is what closes algorithm confusion.
    CHECK(!verify_hs512(mint("{\"typ\":\"JWT\",\"alg\":\"HS256\"}", platform_payload(1788900000)),
                        default_options(), at_epoch(1788890000))
               .ok);
}

void an_expired_token_is_rejected_but_the_leeway_is_honoured() {
    const std::string token = mint(kHs512Header, platform_payload(1788900000));
    JwtVerifyOptions opts = default_options();
    opts.leeway_seconds = 300;

    CHECK(verify_hs512(token, opts, at_epoch(1788900000 + 299)).ok);   // inside the skew allowance
    CHECK(!verify_hs512(token, opts, at_epoch(1788900000 + 301)).ok);  // past it
}

void a_token_without_exp_is_rejected() {
    // No exp means a leaked token is valid forever, which is exactly what the day-key rotation
    // exists to prevent — so an unbounded token is refused rather than treated as long-lived.
    const std::string payload =
        "{\"iss\":\"envfish\",\"aud\":\"fishfind.info\",\"sub\":\"cproxy\",\"server\":\"X\"}";
    CHECK(!verify_hs512(mint(kHs512Header, payload), default_options(), at_epoch(1788890000)).ok);
}

void issuer_audience_and_subject_are_all_enforced() {
    const auto now = at_epoch(1788890000);
    CHECK(!verify_hs512(mint(kHs512Header, platform_payload(1788900000, "X", "1", "someone-else")),
                        default_options(), now)
               .ok);
    CHECK(!verify_hs512(
               mint(kHs512Header, platform_payload(1788900000, "X", "1", "envfish", "elsewhere")),
               default_options(), now)
               .ok);
    CHECK(!verify_hs512(mint(kHs512Header, platform_payload(1788900000, "X", "1", "envfish",
                                                           "fishfind.info", "docapi")),
                        default_options(), now)
               .ok);
}

void an_unchecked_claim_accepts_anything() {
    JwtVerifyOptions opts = default_options();
    opts.issuer.clear();  // CPROXY_JWT_ISSUER=NONE
    CHECK(verify_hs512(mint(kHs512Header, platform_payload(1788900000, "X", "1", "whoever")), opts,
                       at_epoch(1788890000))
              .ok);
}

void an_array_audience_matches_when_it_contains_the_expected_value() {
    const std::string payload =
        "{\"iss\":\"envfish\",\"exp\":1788900000,\"aud\":[\"other\",\"fishfind.info\"],"
        "\"sub\":\"cproxy\",\"server\":\"X\",\"user\":\"7\"}";
    CHECK(verify_hs512(mint(kHs512Header, payload), default_options(), at_epoch(1788890000)).ok);
}

void a_numeric_user_claim_is_read_without_losing_digits() {
    // The frontend sends `user` as a string precisely because the product overflows a double, but a
    // hand-built token may use a number; reading it must not go through a float.
    const std::string payload =
        "{\"iss\":\"envfish\",\"exp\":1788900000,\"aud\":\"fishfind.info\",\"sub\":\"cproxy\","
        "\"server\":\"X\",\"user\":9007199254740993}";
    const JwtResult result =
        verify_hs512(mint(kHs512Header, payload), default_options(), at_epoch(1788890000));
    CHECK(result.ok);
    CHECK(result.claims.user == "9007199254740993");
}

void malformed_input_never_throws_and_never_verifies() {
    const auto opts = default_options();
    const auto now = at_epoch(1788890000);
    static const char* const bad_tokens[] = {"",   "not-a-token", "a.b", "a.b.c.d",
                                             "...", "!!!.???.###", "eyJhbGciOiJIUzUxMiJ9..", "a.b.c"};
    for (const char* bad : bad_tokens) {
        CHECK(!verify_hs512(bad, opts, now).ok);
    }
}

void verification_is_off_entirely_without_a_secret() {
    JwtVerifyOptions opts = default_options();
    opts.secret.clear();
    CHECK(!verify_hs512(mint(kHs512Header, platform_payload(1788900000)), opts,
                        at_epoch(1788890000))
               .ok);
}

void bearer_extraction_handles_the_shapes_a_client_actually_sends() {
    CHECK(bearer_token("Bearer abc.def.ghi") == "abc.def.ghi");
    CHECK(bearer_token("bearer abc.def.ghi") == "abc.def.ghi");  // scheme is case-insensitive
    CHECK(bearer_token("BEARER   abc.def.ghi  ") == "abc.def.ghi");
    CHECK(bearer_token("").empty());
    CHECK(bearer_token("Basic dXNlcjpwYXNz").empty());
    CHECK(bearer_token("Bearer").empty());
    CHECK(bearer_token("Bearer ").empty());
    CHECK(bearer_token("Bearerabc").empty());  // no separator: not a Bearer credential
}

void base64url_decoding_accepts_the_unpadded_form_and_rejects_junk() {
    std::string out;
    CHECK(base64url_decode("", out) && out.empty());
    CHECK(base64url_decode(base64url_encode("hello"), out) && out == "hello");
    CHECK(base64url_decode(base64url_encode(std::string("\xFB\xFF", 2)), out) &&
          out == std::string("\xFB\xFF", 2));  // - and _ are the base64url-specific characters
    CHECK(base64url_decode("aGVsbG8=", out) && out == "hello");  // padding tolerated
    CHECK(!base64url_decode("a+/b", out));                        // standard-base64 characters
    CHECK(!base64url_decode("abcde", out));                       // impossible length

    // Non-zero unused low bits in the final symbol: non-canonical, so refused (RFC 4648 §3.5).
    CHECK(base64url_decode("ww", out) && out == "\xC3");  // 2-symbol tail, 4 unused bits, all 0
    CHECK(!base64url_decode("wx", out));                   // ...the prod case, 'w' -> 'x'
    CHECK(!base64url_decode("w_", out));
    CHECK(base64url_decode("QUI", out) && out == "AB");   // 3-symbol tail, 2 unused bits, all 0
    CHECK(!base64url_decode("QUJ", out));
    CHECK(!base64url_decode("QUL", out));
    CHECK(base64url_decode("aGVsbG8=", out) && out == "hello");
    CHECK(!base64url_decode("aGVsbG9=", out));  // padding does not excuse a non-canonical tail
}

void a_signature_respelled_in_its_unused_low_bits_is_refused() {
    // Seen live on prod 2026-09-11: an HS512 token whose signature ended in 'w' still verified with
    // that char changed to 'x'. 86 symbols carry 516 bits for a 512-bit MAC, so the last symbol has 4
    // unused low bits; the decoder used to throw them away, and all 16 spellings decoded to the same
    // MAC. Not a forgery — the MAC bytes are identical — but a malleable token, which a strict JWS
    // verifier refuses. Every respelling must now fail at decode, before the MAC is even compared.
    const std::string token = mint(kHs512Header, platform_payload(1788900000));
    const std::size_t signature_at = token.rfind('.') + 1;
    const std::string signature = token.substr(signature_at);
    std::string mac;
    CHECK(signature.size() == 86);
    CHECK(base64url_decode(signature, mac) && mac.size() == 64);
    CHECK(verify_hs512(token, default_options(), at_epoch(1788890000)).ok);

    for (unsigned low = 1; low < 16; ++low) {
        const std::string respelled = respell_last_symbol(signature, low);
        CHECK(respelled != signature);
        CHECK(respelled.substr(0, 85) == signature.substr(0, 85));
        CHECK(!base64url_decode(respelled, mac));

        const JwtResult result = verify_hs512(token.substr(0, signature_at) + respelled,
                                              default_options(), at_epoch(1788890000));
        CHECK(!result.ok);
        CHECK(!result.signature_ok);
        CHECK(result.error == "base64url decode failed");
    }
}


// --- Authentic-but-out-of-time-range signals (clock alignment, 0.11.0) -------------------------
// and the `adm` claim, which 0.12.0 stopped reading (privilege now comes from the account mirror).

void a_token_carrying_any_adm_claim_still_verifies_and_the_claim_is_ignored() {
    // A frontend minted `adm` between 0.11.0 and 0.12.0, and prod keeps doing so until its DLL is
    // redeployed -- so a token carrying it, in any shape, must still verify exactly as one without it.
    // JwtClaims has no admin field at all, so there is nothing here that could read it: the only
    // thing left to pin is that its presence is harmless, not fatal.
    static const char* const adm_variants[] = {
        "", ",\"adm\":true", ",\"adm\":false", ",\"adm\":\"true\"", ",\"adm\":1", ",\"adm\":null",
    };
    for (const char* adm : adm_variants) {
        const std::string payload =
            "{\"iss\":\"envfish\",\"iat\":1788880000,\"exp\":1788900000,"
            "\"aud\":\"fishfind.info\",\"sub\":\"cproxy\",\"server\":\"20C23A17-DEAD-BEEF\""
            + std::string(adm) + "}";
        const JwtResult result = verify_hs512(mint(kHs512Header, payload), default_options(),
                                              at_epoch(1788890000));
        CHECK(result.ok);
        CHECK(result.claims.server == "20C23A17-DEAD-BEEF");
    }
}

void an_expired_token_still_reports_its_claims_so_the_skew_can_be_measured() {
    // The point of `signature_ok` / `time_rejected`. Skew larger than the leeway rejects exactly the
    // tokens that could report it, so without this the clock correction could only ever run while
    // the clocks were already close enough not to need it.
    const std::string token = mint(kHs512Header,
                                   "{\"iss\":\"envfish\",\"iat\":1788880000,\"exp\":1788900000,"
                                   "\"aud\":\"fishfind.info\",\"sub\":\"cproxy\","
                                   "\"server\":\"20C23A17-DEAD-BEEF\",\"adm\":true}");
    JwtVerifyOptions opts = default_options();
    opts.leeway_seconds = 60;

    // A full day past exp.
    const JwtResult result = verify_hs512(token, opts, at_epoch(1788900000 + 86400));
    CHECK(!result.ok);
    CHECK(result.error == "token expired");
    CHECK(result.signature_ok);
    CHECK(result.time_rejected);
    CHECK(result.claims.expires_at == 1788900000);  // readable despite ok == false
}

void a_forged_token_reports_neither_signature_ok_nor_time_rejected() {
    // The other half of the contract: nothing about a token that failed its MAC may be believed, so
    // a forgery can never reach the clock-alignment path whatever it claims.
    const std::string token =
        mint(kHs512Header,
             "{\"iss\":\"envfish\",\"iat\":1788880000,\"exp\":1788900000,"
             "\"aud\":\"fishfind.info\",\"sub\":\"cproxy\",\"server\":\"X\",\"adm\":true}",
             "the-wrong-secret-entirely-but-still-long-enough-to-hmac-with");
    const JwtResult result = verify_hs512(token, default_options(), at_epoch(1788890000));

    CHECK(!result.ok);
    CHECK(!result.signature_ok);
    CHECK(!result.time_rejected);
}

void a_wrong_audience_is_not_a_time_rejection_even_when_also_expired() {
    // Identity claims are checked BEFORE the time claims precisely so this cannot be a
    // `time_rejected`: a token for a different audience must not be able to correct our clock, no
    // matter how authentic its signature.
    const std::string token = mint(kHs512Header, platform_payload(1788900000, "S", "1", "envfish",
                                                                 "someone-else.example", "cproxy"));
    const JwtResult result = verify_hs512(token, default_options(), at_epoch(1788900000 + 86400));

    CHECK(!result.ok);
    CHECK(result.signature_ok);
    CHECK(!result.time_rejected);
    CHECK(result.error == "audience mismatch");
}

void a_token_missing_exp_is_authentic_but_never_a_time_rejection() {
    // Authentic yet malformed. It says nothing trustworthy about what time it is, so it must not
    // arm the correction path either.
    const std::string token =
        mint(kHs512Header, "{\"iss\":\"envfish\",\"aud\":\"fishfind.info\","
                           "\"sub\":\"cproxy\",\"server\":\"S\",\"adm\":true}");
    const JwtResult result = verify_hs512(token, default_options(), at_epoch(1788890000));

    CHECK(!result.ok);
    CHECK(result.signature_ok);
    CHECK(!result.time_rejected);
    CHECK(result.error == "missing exp");
}


void a_token_from_the_0_11_frontend_with_adm_still_verifies() {
    // GOLDEN CROSS-LANGUAGE FIXTURES from the shipped C# minter (FishTracker.FishApiJwt.Build, by
    // reflection on the built FishTracker.dll, 2026-09-10) with the same test secret: one minted for
    // an admin, carrying `"adm":true`, and one for an ordinary account a moment earlier.
    //
    // 0.12.0 ignores `adm`, so the two must now verify IDENTICALLY -- both ok, same claims. This is
    // the compatibility guarantee for the rollout window: production's frontend keeps minting `adm`
    // until its DLL is redeployed, and those tokens must keep working through a gateway that no
    // longer believes them.
    const std::string admin_minted_by_dotnet =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9."
        "eyJpc3MiOiJlbnZmaXNoIiwiaWF0IjoxNzg5MDEzOTM1LCJleHAiOjE3ODkwODQ3OTksImF1ZCI6ImZpc2hmaW5kLmlu"
        "Zm8iLCJzdWIiOiJjcHJveHkiLCJzZXJ2ZXIiOiIyMEMyM0ExNy1ERUFELUJFRUYiLCJ1c2VyIjoiMjM5MjQ3MzkyNDcy"
        "Mzk4NCIsImFkbSI6dHJ1ZX0."
        "1JI8B6Qo892XrfjWhSRTMMQcenpoqwkKWHuyvuOcChkATH7VP75IUNE3eXLds414At3vYxfUVQmxmGj1zt3wCA";
    const std::string plain_minted_by_dotnet =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9."
        "eyJpc3MiOiJlbnZmaXNoIiwiaWF0IjoxNzg5MDEzOTM1LCJleHAiOjE3ODkwODQ3OTksImF1ZCI6ImZpc2hmaW5kLmlu"
        "Zm8iLCJzdWIiOiJjcHJveHkiLCJzZXJ2ZXIiOiIyMEMyM0ExNy1ERUFELUJFRUYiLCJ1c2VyIjoiMjM5MjQ3MzkyNDcy"
        "Mzk4NCJ9."
        "jsSHuFQrbGvSod5Yl2ZQSfd_G4T2KMgp94NPbMzu-ed51UaD24VFTbrqVdBr0kNg3Fb-oIpnhtNYBH4zWi_LnA";

    const JwtResult admin = verify_hs512(admin_minted_by_dotnet, default_options(), at_epoch(1789020000));
    const JwtResult plain = verify_hs512(plain_minted_by_dotnet, default_options(), at_epoch(1789020000));
    CHECK(admin.ok);
    CHECK(plain.ok);
    CHECK(admin.claims.user == plain.claims.user);
    CHECK(admin.claims.server == plain.claims.server);
    CHECK(admin.claims.expires_at == plain.claims.expires_at);
}

}  // namespace

int main() {
    a_well_formed_platform_token_verifies_and_yields_both_claims();
    a_token_minted_by_the_real_frontend_verifies();
    a_token_signed_with_a_different_secret_is_rejected();
    a_tampered_payload_is_rejected();
    the_alg_none_forgery_is_rejected();
    a_weaker_hmac_algorithm_is_rejected_before_the_signature_is_even_checked();
    an_expired_token_is_rejected_but_the_leeway_is_honoured();
    a_token_without_exp_is_rejected();
    issuer_audience_and_subject_are_all_enforced();
    an_unchecked_claim_accepts_anything();
    an_array_audience_matches_when_it_contains_the_expected_value();
    a_numeric_user_claim_is_read_without_losing_digits();
    malformed_input_never_throws_and_never_verifies();
    verification_is_off_entirely_without_a_secret();
    bearer_extraction_handles_the_shapes_a_client_actually_sends();
    base64url_decoding_accepts_the_unpadded_form_and_rejects_junk();
    a_signature_respelled_in_its_unused_low_bits_is_refused();
    a_token_carrying_any_adm_claim_still_verifies_and_the_claim_is_ignored();
    a_token_from_the_0_11_frontend_with_adm_still_verifies();
    an_expired_token_still_reports_its_claims_so_the_skew_can_be_measured();
    a_forged_token_reports_neither_signature_ok_nor_time_rejected();
    a_wrong_audience_is_not_a_time_rejection_even_when_also_expired();
    a_token_missing_exp_is_authentic_but_never_a_time_rejection();
    std::cout << "jwt_verifier_test: all checks passed\n";
    return 0;
}
