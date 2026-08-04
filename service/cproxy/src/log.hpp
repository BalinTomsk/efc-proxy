#pragma once

#include <string>

namespace cproxy {

/**
 * Process-wide logging. Mirrors the waterservice logging functionality: structured JSON lines to the
 * console AND to a daily-rolling file with bounded retention.
 *
 * With a non-empty directory, every line is also appended to `<dir>/cproxy.log`; at the first write of
 * a new UTC day the active file is rolled to `<dir>/cproxy.<YYYY-MM-DD>.log` and files older than
 * `max_history` days are pruned. An empty directory means console-only.
 *
 * @param dir          log directory (empty => stdout only)
 * @param max_history  days of rolled files to keep (<= 0 disables pruning)
 */
void init_logging(const std::string& dir, int max_history = 7);

/** Emits `{"ts":...,"service":"cproxy","msg":"<escaped msg>"}` to console + file. */
void log_line(const std::string& msg);

/** Writes a pre-built JSON line verbatim (plus newline) to console + file. */
void log_raw(const std::string& json_line);

}  // namespace cproxy
