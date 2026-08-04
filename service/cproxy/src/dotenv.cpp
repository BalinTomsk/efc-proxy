#include "dotenv.hpp"

#include <cstdlib>
#include <fstream>
#include <string>

#include "secret_codec.hpp"

namespace cproxy {

namespace {

std::string trim(const std::string& s) {
    auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

}  // namespace

std::map<std::string, std::string> load_dotenv(const std::string& path) {
    std::map<std::string, std::string> out;
    if (path.empty()) return out;

    std::ifstream file(path);
    if (!file) return out;  // dotenv is optional — a missing file is not an error

    std::string line;
    while (std::getline(file, line)) {
        const std::string s = trim(line);
        if (s.empty() || s[0] == '#') continue;
        const auto eq = s.find('=');
        if (eq == std::string::npos || eq == 0) continue;

        const std::string key = trim(s.substr(0, eq));
        const std::string raw = trim(s.substr(eq + 1));
        out[key] = decrypt_if_needed(key, raw);  // throws on encrypted value with no/wrong key
    }
    return out;
}

EnvLookup make_env_lookup(const std::map<std::string, std::string>& dotenv) {
    return [dotenv](const char* name) -> std::optional<std::string> {
        if (const char* v = std::getenv(name); v != nullptr && *v != '\0') {
            return std::string(v);  // real environment always wins
        }
        auto it = dotenv.find(name);
        if (it == dotenv.end()) return std::nullopt;
        return it->second;
    };
}

}  // namespace cproxy
