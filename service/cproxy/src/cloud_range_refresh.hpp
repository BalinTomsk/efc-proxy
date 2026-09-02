#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "cloud_range_store.hpp"
#include "config.hpp"

namespace cproxy {

/** Outcome of fetching one provider's published feed. */
struct FeedResult {
    std::string provider;
    std::vector<std::string> cidrs;  // raw CIDR strings, IPv4 and IPv6 mixed; IPv6 is dropped later
    bool ok = false;
    std::string error;
};

/** Providers this build knows how to fetch, in the frontend script's order. */
std::vector<std::string> known_cloud_providers();

/**
 * Fetches one provider's feed over HTTPS. Mirrors `Update-CloudProviderRanges.ps1` in the
 * `envfish-db` repo — same URLs, same fields, same two quirks it documents (GCP entries with no
 * `ipv4Prefix`, and DigitalOcean's CSV arriving without a text content-type).
 */
FeedResult fetch_provider(const std::string& provider, int timeout_seconds);

/**
 * One full refresh cycle: fetch every provider in `cfg.cloudrange_providers`, then replace the rows
 * of the providers that succeeded in a single transaction, preserving manual `disabled` overrides
 * per (provider, cidr). A provider whose feed fails keeps its existing rows — a partial run never
 * wipes what it could not re-fetch, exactly as the PowerShell version behaves.
 *
 * Returns the number of IPv4 ranges written. Throws only on a database failure; feed failures are
 * reported through the log and reflected in the return value.
 *
 * When every feed fails the database is left completely untouched: with no fresh data, keeping the
 * previous set beats both wiping it (blocks nothing) and half-writing it.
 */
std::size_t refresh_cloud_ranges(const Config& cfg, CloudRangeStore& store);

/**
 * Owns the background refresh thread. Sleeps `cfg.cloudrange_refresh_hours` between cycles and
 * wakes immediately on stop, so shutdown never waits out a two-week timer.
 *
 * Deliberately NOT started by install_routes(): the tests stand proxies up in-process and must
 * never reach out to the internet. `main` owns the worker.
 */
class CloudRangeRefresher {
public:
    CloudRangeRefresher(const Config& cfg, CloudRangeStore& store);
    ~CloudRangeRefresher();

    CloudRangeRefresher(const CloudRangeRefresher&) = delete;
    CloudRangeRefresher& operator=(const CloudRangeRefresher&) = delete;

    /** Starts the thread. No-op when the feature is not configured. */
    void start();
    /** Signals the thread to finish and joins it. */
    void stop();

private:
    void run();

    const Config& cfg_;
    CloudRangeStore& store_;
    std::thread thread_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool stopping_ = false;
};

}  // namespace cproxy
