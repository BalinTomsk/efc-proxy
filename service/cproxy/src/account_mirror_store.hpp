#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace cproxy {

class AccountMirrorStore {
public:
    explicit AccountMirrorStore(std::string db_path);

    const std::string& db_path() const { return db_path_; }
    void ensure_schema();
    bool apply_event(const nlohmann::json& event);

private:
    std::string db_path_;
};

}  // namespace cproxy
