#pragma once
// CHECK: assert() replacement that survives Release builds. The Docker image builds with
// CMAKE_BUILD_TYPE=Release (-DNDEBUG), which compiles assert() out entirely - the suite was
// passing vacuously. CHECK always evaluates and fails the test process with a location message.
#include <cstdio>
#include <cstdlib>

#define CHECK(cond)                                                                          \
    do {                                                                                     \
        if (!(cond)) {                                                                       \
            std::fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);   \
            std::exit(1);                                                                    \
        }                                                                                    \
    } while (0)
