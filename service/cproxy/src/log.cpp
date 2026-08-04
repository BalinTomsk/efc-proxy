#include "log.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <mutex>
#include <system_error>

namespace fs = std::filesystem;

namespace cproxy {

namespace {

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out += std::format("\\u{:04x}", static_cast<int>(static_cast<unsigned char>(c)));
                } else {
                    out += c;
                }
        }
    }
    return out;
}

/** Current UTC date as "YYYY-MM-DD". */
std::string today_str() {
    auto d = std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now());
    return std::format("{:%F}", d);
}

/** Parses "YYYY-MM-DD" to sys_days; returns the epoch (count 0) on failure. */
std::chrono::sys_days parse_day(const std::string& ymd) {
    int y = 0, m = 0, d = 0;
    if (std::sscanf(ymd.c_str(), "%d-%d-%d", &y, &m, &d) != 3) return std::chrono::sys_days{};
    return std::chrono::sys_days{std::chrono::year{y} / std::chrono::month{static_cast<unsigned>(m)} /
                                 std::chrono::day{static_cast<unsigned>(d)}};
}

/**
 * Console + optional daily-rolling-file sink. All public methods are serialized by one mutex so log
 * lines never interleave across the proxy's worker threads.
 */
class Logger {
public:
    void init(const std::string& dir, int max_history) {
        std::lock_guard<std::mutex> lock(mu_);
        dir_ = dir;
        max_history_ = max_history;
        if (!dir_.empty()) {
            std::error_code ec;
            fs::create_directories(dir_, ec);
            current_day_ = today_str();
            out_.open(active_path(), std::ios::app);
        }
    }

    void write(const std::string& line) {
        std::lock_guard<std::mutex> lock(mu_);
        std::cout << line << '\n';
        std::cout.flush();
        if (out_.is_open()) {
            const std::string today = today_str();
            if (today != current_day_) rollover(today);
            out_ << line << '\n';
            out_.flush();  // durable per line — matches logback's immediateFlush default
        }
    }

private:
    std::string active_path() const { return dir_ + "/cproxy.log"; }
    std::string dated_path(const std::string& day) const { return dir_ + "/cproxy." + day + ".log"; }

    void rollover(const std::string& new_day) {
        out_.close();
        std::error_code ec;
        fs::rename(active_path(), dated_path(current_day_), ec);  // best-effort; ignore if absent
        current_day_ = new_day;
        out_.open(active_path(), std::ios::trunc);
        prune();
    }

    void prune() {
        if (max_history_ <= 0) return;
        const auto cutoff = std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now()) -
                            std::chrono::days{max_history_};
        std::error_code ec;
        // "cproxy.YYYY-MM-DD.log" — 21 chars; "cproxy.log" (10) is deliberately excluded.
        const std::size_t dated_len = std::string("cproxy.YYYY-MM-DD.log").size();
        for (const auto& entry : fs::directory_iterator(dir_, ec)) {
            const std::string name = entry.path().filename().string();
            if (name.rfind("cproxy.", 0) != 0 || name.size() != dated_len) continue;
            const auto day = parse_day(name.substr(7, 10));
            if (day.time_since_epoch().count() != 0 && day < cutoff) {
                fs::remove(entry.path(), ec);
            }
        }
    }

    std::mutex mu_;
    std::string dir_;
    int max_history_ = 7;
    std::ofstream out_;
    std::string current_day_;
};

Logger& instance() {
    static Logger logger;
    return logger;
}

}  // namespace

void init_logging(const std::string& dir, int max_history) {
    instance().init(dir, max_history);
}

void log_raw(const std::string& json_line) {
    instance().write(json_line);
}

void log_line(const std::string& msg) {
    const auto now = std::chrono::system_clock::now();
    log_raw(std::format("{{\"ts\":\"{:%FT%TZ}\",\"service\":\"cproxy\",\"msg\":\"{}\"}}",
                        std::chrono::floor<std::chrono::seconds>(now), json_escape(msg)));
}

}  // namespace cproxy
