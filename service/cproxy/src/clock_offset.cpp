#include "clock_offset.hpp"

#include <algorithm>

namespace cproxy {

bool ClockOffset::adopt(long long delta_seconds, int max_abs_seconds) {
    if (max_abs_seconds < 0) {
        max_abs_seconds = 0;
    }
    const long long cap = static_cast<long long>(max_abs_seconds);

    // compare_exchange rather than fetch_add: the clamp is computed from the value being replaced,
    // so two concurrent admin requests must not both add their delta to the same starting offset and
    // land at twice the correction. The loop re-clamps against whatever won.
    long long current = offset_.load();
    for (;;) {
        const long long proposed = std::clamp(current + delta_seconds, -cap, cap);
        if (proposed == current) {
            return false;
        }
        if (offset_.compare_exchange_weak(current, proposed)) {
            return true;
        }
    }
}

}  // namespace cproxy
