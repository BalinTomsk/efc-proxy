#include "cloud_range_refresh.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <format>
#include <regex>
#include <stdexcept>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "log.hpp"

namespace cproxy {

namespace {

using nlohmann::json;

/**
 * Providers without a clean first-party feed are resolved through RIPEstat's announced-prefixes
 * API, keyed by ASN. Same ASN list as the PowerShell refresher — keep the two in step.
 */
const std::vector<std::pair<std::string, std::vector<int>>>& asn_providers() {
    static const std::vector<std::pair<std::string, std::vector<int>>> table = {
        {"Alibaba", {45102, 45103, 37963, 134963}},
        {"Linode", {63949}},
        {"Vultr", {20473}},
        {"Hetzner", {24940, 213230}},
        {"OVH", {16276}},
        {"Scaleway", {12876}},
        {"Tencent", {132203, 45090}},
    };
    return table;
}

/** Splits "https://host/path" into an origin httplib can dial and the path to request. */
std::pair<std::string, std::string> split_url(const std::string& url) {
    const std::size_t scheme = url.find("://");
    if (scheme == std::string::npos) return {url, "/"};
    const std::size_t slash = url.find('/', scheme + 3);
    if (slash == std::string::npos) return {url, "/"};
    return {url.substr(0, slash), url.substr(slash)};
}

/** One HTTPS GET. Throws on transport failure or a non-2xx status. */
std::string http_get(const std::string& url, int timeout_seconds) {
    const auto [origin, path] = split_url(url);
    httplib::Client cli(origin);
    cli.set_connection_timeout(timeout_seconds, 0);
    cli.set_read_timeout(timeout_seconds, 0);
    cli.set_follow_location(true);  // Azure's ServiceTags link redirects
    cli.set_keep_alive(false);
    // Some provider CDNs serve a default page to a client that sends no UA.
    cli.set_default_headers({{"User-Agent", "cproxy-cloudranges/1.0"}});

    auto res = cli.Get(path.c_str());
    if (!res) {
        throw std::runtime_error(
            std::format("GET {} failed: {}", url, httplib::to_string(res.error())));
    }
    if (res->status < 200 || res->status >= 300) {
        throw std::runtime_error(std::format("GET {} returned HTTP {}", url, res->status));
    }
    return res->body;
}

std::vector<std::string> fetch_aws(int t) {
    const json doc = json::parse(http_get("https://ip-ranges.amazonaws.com/ip-ranges.json", t));
    std::vector<std::string> out;
    for (const auto& p : doc.value("prefixes", json::array())) {
        if (p.contains("ip_prefix") && p["ip_prefix"].is_string()) {
            out.push_back(p["ip_prefix"].get<std::string>());
        }
    }
    return out;
}

std::vector<std::string> fetch_gcp(int t) {
    const json doc = json::parse(http_get("https://www.gstatic.com/ipranges/cloud.json", t));
    std::vector<std::string> out;
    for (const auto& p : doc.value("prefixes", json::array())) {
        // QUIRK (documented in the PowerShell refresher): IPv6-only entries carry no `ipv4Prefix`
        // at all. Reading it unguarded is what broke the whole GCP fetch there under StrictMode;
        // the C++ equivalent of that bug would be operator[] default-constructing a null.
        if (p.contains("ipv4Prefix") && p["ipv4Prefix"].is_string()) {
            out.push_back(p["ipv4Prefix"].get<std::string>());
        }
    }
    return out;
}

std::vector<std::string> fetch_oracle(int t) {
    const json doc =
        json::parse(http_get("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", t));
    std::vector<std::string> out;
    for (const auto& region : doc.value("regions", json::array())) {
        for (const auto& c : region.value("cidrs", json::array())) {
            if (c.contains("cidr") && c["cidr"].is_string()) {
                out.push_back(c["cidr"].get<std::string>());
            }
        }
    }
    return out;
}

std::vector<std::string> fetch_digitalocean(int t) {
    // QUIRK: this endpoint sends no text content-type. That only mattered for PowerShell, which
    // handed back a byte[]; here the body is already bytes, so it just needs splitting. The first
    // CSV field is the CIDR.
    const std::string body = http_get("https://www.digitalocean.com/geo/google.csv", t);
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos <= body.size()) {
        std::size_t nl = body.find('\n', pos);
        if (nl == std::string::npos) nl = body.size();
        std::string line = body.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const std::size_t comma = line.find(',');
        std::string first = comma == std::string::npos ? line : line.substr(0, comma);
        // trim
        const auto b = first.find_first_not_of(" \t");
        const auto e = first.find_last_not_of(" \t");
        if (b == std::string::npos) continue;
        first = first.substr(b, e - b + 1);
        if (!first.empty()) out.push_back(first);
        if (nl == body.size()) break;
    }
    return out;
}

std::vector<std::string> fetch_azure(int t) {
    // The download page embeds a weekly-rotating direct link to ServiceTags_Public_<date>.json.
    const std::string page =
        http_get("https://www.microsoft.com/en-us/download/details.aspx?id=56519", t);
    static const std::regex link_re(
        R"(https://download\.microsoft\.com/download/[^"']*ServiceTags_Public_[0-9]+\.json)");
    std::smatch m;
    if (!std::regex_search(page, m, link_re)) {
        throw std::runtime_error("could not locate the ServiceTags_Public JSON link on the Azure "
                                 "download page");
    }
    const json doc = json::parse(http_get(m.str(), t));
    std::vector<std::string> out;
    for (const auto& v : doc.value("values", json::array())) {
        const auto props = v.value("properties", json::object());
        for (const auto& p : props.value("addressPrefixes", json::array())) {
            if (!p.is_string()) continue;
            const std::string s = p.get<std::string>();
            if (s.find(':') == std::string::npos) out.push_back(s);  // IPv4 only
        }
    }
    return out;
}

std::vector<std::string> fetch_asn(const std::vector<int>& asns, int t) {
    std::vector<std::string> out;
    for (int asn : asns) {
        const json doc = json::parse(http_get(
            std::format("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}",
                        asn),
            t));
        const auto data = doc.value("data", json::object());
        for (const auto& p : data.value("prefixes", json::array())) {
            if (p.contains("prefix") && p["prefix"].is_string()) {
                out.push_back(p["prefix"].get<std::string>());
            }
        }
    }
    return out;
}

std::string utc_now_iso() {
    const auto now = std::chrono::system_clock::now();
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}",
                       std::chrono::floor<std::chrono::seconds>(now));
}

/** RAII sqlite handle. */
struct SqliteDb {
    sqlite3* db = nullptr;
    ~SqliteDb() {
        if (db != nullptr) sqlite3_close(db);
    }
};

void exec_or_throw(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        const std::string msg = err != nullptr ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error(std::format("cloud-range db statement failed: {}", msg));
    }
}

std::string sql_quote(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "''";
        else out += c;
    }
    out += "'";
    return out;
}

}  // namespace

std::vector<std::string> known_cloud_providers() {
    std::vector<std::string> out = {"AWS", "GCP", "Azure", "Oracle", "DigitalOcean"};
    for (const auto& [name, asns] : asn_providers()) out.push_back(name);
    return out;
}

FeedResult fetch_provider(const std::string& provider, int timeout_seconds) {
    FeedResult r;
    r.provider = provider;
    try {
        if (provider == "AWS") r.cidrs = fetch_aws(timeout_seconds);
        else if (provider == "GCP") r.cidrs = fetch_gcp(timeout_seconds);
        else if (provider == "Oracle") r.cidrs = fetch_oracle(timeout_seconds);
        else if (provider == "DigitalOcean") r.cidrs = fetch_digitalocean(timeout_seconds);
        else if (provider == "Azure") r.cidrs = fetch_azure(timeout_seconds);
        else {
            const auto& table = asn_providers();
            const auto it = std::find_if(table.begin(), table.end(),
                                         [&](const auto& e) { return e.first == provider; });
            if (it == table.end()) {
                r.error = std::format("unknown provider '{}'", provider);
                return r;
            }
            r.cidrs = fetch_asn(it->second, timeout_seconds);
        }
        r.ok = true;
    } catch (const std::exception& ex) {
        r.error = ex.what();
    }
    return r;
}

std::size_t refresh_cloud_ranges(const Config& cfg, CloudRangeStore& store) {
    if (cfg.cloudrange_db_path.empty() || cfg.cloudrange_providers.empty()) return 0;

    ensure_cloud_range_schema(cfg.cloudrange_db_path);

    // --- 1. Fetch every requested provider -------------------------------------------------
    struct Row {
        std::string provider;
        std::string cidr;
        IpRange range;
    };
    std::vector<Row> rows;
    std::vector<std::string> refreshed;

    for (const std::string& provider : cfg.cloudrange_providers) {
        const FeedResult feed = fetch_provider(provider, cfg.cloudrange_fetch_timeout_seconds);
        if (!feed.ok) {
            log_raw(std::format(
                "{{\"service\":\"cproxy\",\"level\":\"WARN\",\"msg\":\"cloud-range feed {} failed, "
                "leaving its existing rows untouched: {}\"}}",
                provider, feed.error));
            continue;
        }
        std::size_t added = 0;
        for (const std::string& cidr : feed.cidrs) {
            const auto range = cidr_to_range(cidr);
            if (!range) continue;  // IPv6 or malformed
            rows.push_back(Row{provider, cidr, *range});
            ++added;
        }
        refreshed.push_back(provider);
        log_raw(std::format("{{\"service\":\"cproxy\",\"msg\":\"cloud-range feed {}: {} IPv4 "
                            "ranges\"}}",
                            provider, added));
    }

    // Every feed failed: leave the database exactly as it was. Wiping would unblock everything,
    // and a half-write would be worse; the previous set is the best available answer.
    if (refreshed.empty()) {
        log_raw("{\"service\":\"cproxy\",\"level\":\"ERROR\",\"msg\":\"cloud-range refresh: no feed "
                "succeeded, database left unchanged\"}");
        return 0;
    }

    // --- 2. Replace the refreshed providers' rows in one transaction -----------------------
    SqliteDb handle;
    if (sqlite3_open_v2(cfg.cloudrange_db_path.c_str(), &handle.db, SQLITE_OPEN_READWRITE,
                        nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::format("failed to open cloud-range database '{}': {}",
                                             cfg.cloudrange_db_path,
                                             handle.db != nullptr ? sqlite3_errmsg(handle.db)
                                                                  : "unknown error"));
    }
    sqlite3_busy_timeout(handle.db, 10000);

    std::string in_list;
    for (const std::string& p : refreshed) {
        if (!in_list.empty()) in_list += ",";
        in_list += sql_quote(p);
    }

    exec_or_throw(handle.db, "BEGIN IMMEDIATE");
    try {
        // Preserve manual `disabled = 1` overrides for the providers about to be replaced, so a
        // range an operator deliberately excluded is not silently re-enabled by the refresh.
        std::vector<std::pair<std::string, std::string>> keep;
        {
            const std::string sel =
                std::format("SELECT provider, cidr FROM cloud_provider_ip_range "
                            "WHERE disabled = 1 AND provider IN ({})",
                            in_list);
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(handle.db, sel.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
                throw std::runtime_error("failed to read disabled overrides");
            }
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                keep.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)),
                                  reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
            }
            sqlite3_finalize(stmt);
        }

        exec_or_throw(handle.db,
                      std::format("DELETE FROM cloud_provider_ip_range WHERE provider IN ({})",
                                  in_list)
                          .c_str());

        const std::string now = utc_now_iso();
        sqlite3_stmt* ins = nullptr;
        static const char* const ins_sql =
            "INSERT OR REPLACE INTO cloud_provider_ip_range"
            " (provider, cidr, ip_start, ip_end, disabled, source, updated_utc)"
            " VALUES (?, ?, ?, ?, 0, 'cproxy-refresh', ?)";
        if (sqlite3_prepare_v2(handle.db, ins_sql, -1, &ins, nullptr) != SQLITE_OK) {
            throw std::runtime_error("failed to prepare cloud-range insert");
        }
        for (const Row& row : rows) {
            sqlite3_reset(ins);
            sqlite3_bind_text(ins, 1, row.provider.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 2, row.cidr.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(ins, 3, static_cast<sqlite3_int64>(row.range.start));
            sqlite3_bind_int64(ins, 4, static_cast<sqlite3_int64>(row.range.end));
            sqlite3_bind_text(ins, 5, now.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(ins) != SQLITE_DONE) {
                sqlite3_finalize(ins);
                throw std::runtime_error("cloud-range insert failed");
            }
        }
        sqlite3_finalize(ins);

        // Re-apply the preserved overrides to any (provider, cidr) still present.
        sqlite3_stmt* upd = nullptr;
        static const char* const upd_sql =
            "UPDATE cloud_provider_ip_range SET disabled = 1 WHERE provider = ? AND cidr = ?";
        if (sqlite3_prepare_v2(handle.db, upd_sql, -1, &upd, nullptr) != SQLITE_OK) {
            throw std::runtime_error("failed to prepare disabled re-apply");
        }
        for (const auto& [provider, cidr] : keep) {
            sqlite3_reset(upd);
            sqlite3_bind_text(upd, 1, provider.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(upd, 2, cidr.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(upd);
        }
        sqlite3_finalize(upd);

        exec_or_throw(handle.db, "COMMIT");
    } catch (...) {
        exec_or_throw(handle.db, "ROLLBACK");
        throw;
    }

    // --- 3. Swap the in-memory set --------------------------------------------------------
    store.reload(cfg.cloudrange_db_path);
    log_raw(std::format("{{\"service\":\"cproxy\",\"msg\":\"cloud-range refresh complete\","
                        "\"providers\":{},\"rows\":{},\"merged_ranges\":{}}}",
                        refreshed.size(), rows.size(), store.size()));
    return rows.size();
}

CloudRangeRefresher::CloudRangeRefresher(const Config& cfg, CloudRangeStore& store)
    : cfg_(cfg), store_(store) {}

CloudRangeRefresher::~CloudRangeRefresher() { stop(); }

void CloudRangeRefresher::start() {
    if (cfg_.cloudrange_db_path.empty() || cfg_.cloudrange_providers.empty()) return;
    if (thread_.joinable()) return;
    thread_ = std::thread([this] { run(); });
}

void CloudRangeRefresher::stop() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        stopping_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void CloudRangeRefresher::run() {
    // The stored set is already usable at startup (main loads it), so the first fetch waits a full
    // interval unless explicitly asked for. Refreshing on every boot would hammer the provider
    // feeds during a redeploy loop for data that changes on the order of weeks.
    bool due = cfg_.cloudrange_refresh_on_start;

    for (;;) {
        if (due) {
            try {
                refresh_cloud_ranges(cfg_, store_);
            } catch (const std::exception& ex) {
                log_raw(std::format("{{\"service\":\"cproxy\",\"level\":\"ERROR\","
                                    "\"msg\":\"cloud-range refresh failed: {}\"}}",
                                    ex.what()));
            }
        }
        due = true;

        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait_for(lock, std::chrono::hours(cfg_.cloudrange_refresh_hours),
                     [this] { return stopping_; });
        if (stopping_) return;
    }
}

}  // namespace cproxy
