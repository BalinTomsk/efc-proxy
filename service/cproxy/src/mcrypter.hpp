#ifndef MACROENCRYPTER_HPP
#define MACROENCRYPTER_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace macroencrypter {
namespace detail {

constexpr std::size_t header_size = 16;
constexpr std::uint32_t blob_magic = 0x3158454Du; // "MEX1"
constexpr std::uint32_t maximum_payload_size = 16u * 1024u * 1024u;

template <std::size_t N>
struct encrypted_blob {
    std::array<std::uint8_t, header_size + N> bytes{};

    const char* data() const noexcept
    {
        return reinterpret_cast<const char*>(bytes.data());
    }
};

template <typename Array>
constexpr void write_u32(Array& output,
                         std::size_t offset,
                         std::uint32_t value) noexcept
{
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 8u);
    output[offset + 2] = static_cast<std::uint8_t>(value >> 16u);
    output[offset + 3] = static_cast<std::uint8_t>(value >> 24u);
}

inline std::uint32_t read_u32(const char* input, std::size_t offset) noexcept
{
    const auto byte = [input](std::size_t index) noexcept {
        return static_cast<std::uint32_t>(
            static_cast<unsigned char>(input[index]));
    };

    return byte(offset) |
           (byte(offset + 1) << 8u) |
           (byte(offset + 2) << 16u) |
           (byte(offset + 3) << 24u);
}

// FNV-1a hashes __FILE__ into the base XOR key at compile time.
template <std::size_t N>
constexpr std::uint64_t file_hash(const char (&file_name)[N]) noexcept
{
    std::uint64_t hash = 14695981039346656037ull;

    for (std::size_t i = 0; i + 1 < N; ++i) {
        hash ^= static_cast<unsigned char>(file_name[i]);
        hash *= 1099511628211ull;
    }

    return hash;
}

constexpr std::uint32_t key_fingerprint(std::uint64_t key) noexcept
{
    return static_cast<std::uint32_t>(key ^ (key >> 32u) ^ 0xA57C3E19u);
}

constexpr std::uint64_t initial_stream_state(std::uint64_t file_key,
                                              std::uint32_t nonce) noexcept
{
    return file_key ^
           (static_cast<std::uint64_t>(nonce) * 0x9E3779B97F4A7C15ull) ^
           0xD1B54A32D192ED03ull;
}

// SplitMix64 supplies a different XOR byte for every character.
constexpr std::uint8_t next_key_byte(std::uint64_t& state) noexcept
{
    state += 0x9E3779B97F4A7C15ull;
    std::uint64_t value = state;
    value = (value ^ (value >> 30u)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27u)) * 0x94D049BB133111EBull;
    value ^= value >> 31u;
    return static_cast<std::uint8_t>(value >> 56u);
}

template <std::uint32_t Nonce, std::size_t N, std::size_t FileNameSize>
constexpr encrypted_blob<N> make_encrypted(
    const char (&plain_text)[N],
    const char (&file_name)[FileNameSize]) noexcept
{
    static_assert(N > 0, "ENCYPTER requires a string literal");
    static_assert(N <= maximum_payload_size, "encrypted literal is too large");

    encrypted_blob<N> output{};
    const std::uint64_t file_key = file_hash(file_name);

    write_u32(output.bytes, 0, blob_magic);
    write_u32(output.bytes, 4, static_cast<std::uint32_t>(N));
    write_u32(output.bytes, 8, Nonce);
    write_u32(output.bytes, 12, key_fingerprint(file_key));

    std::uint64_t state = initial_stream_state(file_key, Nonce);
    for (std::size_t i = 0; i < N; ++i) {
        output.bytes[header_size + i] =
            static_cast<std::uint8_t>(
                static_cast<unsigned char>(plain_text[i]) ^ next_key_byte(state));
    }

    return output;
}

struct decryption_cache {
    std::mutex mutex;
    std::unordered_map<const void*, std::string> values;
};

inline decryption_cache& cache()
{
    static decryption_cache instance;
    return instance;
}

} // namespace detail

// The returned pointer remains valid for the rest of the process.
inline const char* decrypt(const char* encrypted_text, std::uint64_t file_key)
{
    if (encrypted_text == nullptr) {
        throw std::invalid_argument("DECRYPTER received a null pointer");
    }

    auto& decryption_cache = detail::cache();
    std::lock_guard<std::mutex> lock(decryption_cache.mutex);

    const auto cached = decryption_cache.values.find(encrypted_text);
    if (cached != decryption_cache.values.end()) {
        return cached->second.c_str();
    }

    if (detail::read_u32(encrypted_text, 0) != detail::blob_magic) {
        throw std::runtime_error("DECRYPTER received an invalid encrypted blob");
    }

    const std::uint32_t payload_size = detail::read_u32(encrypted_text, 4);
    const std::uint32_t nonce = detail::read_u32(encrypted_text, 8);
    const std::uint32_t fingerprint = detail::read_u32(encrypted_text, 12);

    if (payload_size == 0 || payload_size > detail::maximum_payload_size) {
        throw std::runtime_error("DECRYPTER found an invalid payload size");
    }

    if (fingerprint != detail::key_fingerprint(file_key)) {
        throw std::runtime_error(
            "DECRYPTER must be called from the same source file as ENCYPTER");
    }

    std::string plain_text(payload_size - 1u, '\0');
    std::uint64_t state = detail::initial_stream_state(file_key, nonce);

    for (std::uint32_t i = 0; i < payload_size; ++i) {
        const auto encrypted_byte = static_cast<std::uint8_t>(
            static_cast<unsigned char>(encrypted_text[detail::header_size + i]));
        const auto plain_byte = static_cast<std::uint8_t>(
            encrypted_byte ^ detail::next_key_byte(state));

        if (i + 1u == payload_size) {
            if (plain_byte != 0u) {
                throw std::runtime_error("DECRYPTER key or payload is invalid");
            }
        } else {
            plain_text[i] = static_cast<char>(plain_byte);
        }
    }

    const auto inserted = decryption_cache.values.emplace(
        encrypted_text, std::move(plain_text));
    return inserted.first->second.c_str();
}

} // namespace macroencrypter

// Keep ENCYPTER for compatibility with the spelling in the requested API.
#define _ENCR(text_literal)                                                \
    ([]() -> const char* {                                                    \
        static constexpr auto macroencrypter_value =                          \
            ::macroencrypter::detail::make_encrypted<                         \
                static_cast<std::uint32_t>(__LINE__)>(text_literal, __FILE__); \
        return macroencrypter_value.data();                                   \
    }())

#define _DECR(encrypted_pointer)                                          \
    (::macroencrypter::decrypt(                                               \
        (encrypted_pointer),                                                  \
        ::macroencrypter::detail::file_hash(__FILE__)))

#define _HIDD(x)  _DECR(_ENCR(x))

#endif // MACROENCRYPTER_HPP
