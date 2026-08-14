#include "secret_codec.hpp"

#include <openssl/evp.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>
#include "mcrypter.hpp"

namespace cproxy {

namespace {

constexpr const char* PREFIX = "enc:v1:";
constexpr int KEY_BYTES = 32;
constexpr int NONCE_BYTES = 12;
constexpr int TAG_BYTES = 16;

using Bytes = std::vector<unsigned char>;

std::string strip_whitespace(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (!std::isspace(static_cast<unsigned char>(c))) out += c;
    }
    return out;
}

bool is_hex(const std::string& s) {
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return !s.empty();
}

Bytes hex_decode(const std::string& s) {
    Bytes out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<unsigned char>(std::stoi(s.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}

int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/** Decodes standard OR url-safe base64 (padding optional). */
Bytes b64_decode(std::string s) {
    for (char& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    Bytes out;
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=' || std::isspace(static_cast<unsigned char>(c))) continue;
        int v = b64_val(static_cast<unsigned char>(c));
        if (v < 0) throw std::runtime_error("invalid base64 character");
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::optional<std::string> getenv_opt(const char* name) {
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') return std::nullopt;
    return std::string(v);
}

/** Reads and caches the 32-byte master key; nullopt when no key source is configured. */
const std::optional<Bytes>& master_key() {
    static std::once_flag once;
    static std::optional<Bytes> key;
    std::call_once(once, [] {
        std::optional<std::string> material;
        if (auto path = getenv_opt(_HIDD("FF_MASTER_KEY_FILE"))) {
            std::ifstream f(*path, std::ios::binary);
            if (!f) throw std::runtime_error("Could not read the master key file at " + *path +
                                             " (from FF_MASTER_KEY_FILE).");
            std::ostringstream ss;
            ss << f.rdbuf();
            material = ss.str();
        } else if (auto inline_key = getenv_opt(_HIDD("FF_MASTER_KEY"))) {
            material = *inline_key;
        }
        if (!material) {
            key = std::nullopt;
            return;
        }
        const std::string compact = strip_whitespace(*material);
        Bytes bytes = (compact.size() == KEY_BYTES * 2 && is_hex(compact)) ? hex_decode(compact)
                                                                           : b64_decode(compact);
        if (bytes.size() != static_cast<std::size_t>(KEY_BYTES)) {
            throw std::runtime_error("Master key must be 32 bytes (64 hex chars or 44 base64 chars); got " +
                                     std::to_string(bytes.size()) + " bytes.");
        }
        key = std::move(bytes);
    });
    return key;
}

std::string aes_256_gcm_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext,
                                const Bytes& tag, const std::string& aad) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<unsigned char> out(ciphertext.size());
    int len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_BYTES, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1;
    if (ok && !aad.empty()) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()),
                               static_cast<int>(aad.size())) == 1;
    }
    int plaintext_len = 0;
    if (ok) {
        ok = EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data(),
                               static_cast<int>(ciphertext.size())) == 1;
        plaintext_len = len;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_BYTES,
                                 const_cast<unsigned char*>(tag.data())) == 1;
    }
    int final_ret = ok ? EVP_DecryptFinal_ex(ctx, out.data() + plaintext_len, &len) : 0;
    EVP_CIPHER_CTX_free(ctx);

    if (!ok || final_ret <= 0) {
        // Deliberately vague: a GCM tag failure means wrong key, wrong variable name, or tampering.
        throw std::runtime_error("The master key does not match the value, or the value was altered.");
    }
    plaintext_len += len;
    return std::string(reinterpret_cast<char*>(out.data()), plaintext_len);
}

}  // namespace

bool is_encrypted(const std::string& value) {
    return value.rfind(PREFIX, 0) == 0;
}

std::string decrypt_if_needed(const std::string& name, const std::string& value) {
    if (!is_encrypted(value)) return value;

    const auto& key = master_key();
    if (!key) {
        throw std::runtime_error("Value of " + name +
                                 " is encrypted but no master key is configured. Set FF_MASTER_KEY_FILE "
                                 "to the key file path (preferred) or FF_MASTER_KEY.");
    }

    Bytes payload;
    try {
        payload = b64_decode(value.substr(std::string(PREFIX).size()));
    } catch (const std::exception&) {
        throw std::runtime_error("Value of " + name + " is marked " + PREFIX + " but is not valid base64url.");
    }
    if (payload.size() < static_cast<std::size_t>(NONCE_BYTES + TAG_BYTES)) {
        throw std::runtime_error("Value of " + name + " is marked " + PREFIX +
                                 " but is too short to be a valid payload.");
    }

    Bytes nonce(payload.begin(), payload.begin() + NONCE_BYTES);
    Bytes tag(payload.end() - TAG_BYTES, payload.end());
    Bytes ciphertext(payload.begin() + NONCE_BYTES, payload.end() - TAG_BYTES);

    try {
        return aes_256_gcm_decrypt(*key, nonce, ciphertext, tag, name);
    } catch (const std::exception& e) {
        throw std::runtime_error("Could not decrypt " + name + ". " + e.what());
    }
}

}  // namespace cproxy
