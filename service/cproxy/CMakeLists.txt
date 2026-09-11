cmake_minimum_required(VERSION 3.20)
project(cproxy VERSION 0.13.1 LANGUAGES CXX)

# C++23 as requested; no compiler extensions so the code stays portable.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# --- HTTP engine: cpp-httplib (header-only server + client) -------------------
# Pinned to a release tag for reproducible builds.
#
# TLS is ON as of 0.8.0. It was deliberately OFF before ("cproxy speaks plain HTTP to the internal
# upstreams, so a lean binary with no libssl runtime dependency is preferred"), and that reasoning
# still holds for the PROXY path — which is unchanged and still plain HTTP to docapi over the VPC.
# What changed is that the cloud-range refresher fetches provider feeds (AWS/GCP/Azure/Oracle/DO and
# RIPEstat) directly, and every one of those is HTTPS-only. Cost of the reversal, accepted knowingly:
# libssl joins libcrypto as a runtime dependency, the image grows, and the proxy now makes outbound
# internet calls it never used to. Zlib/brotli stay OFF — nothing needs them.
include(FetchContent)
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE ON  CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE   OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG        v0.15.3
)
FetchContent_MakeAvailable(httplib)

# --- JSON: nlohmann/json (header-only) ----------------------------------------
# Needed only by the cloud-range refresher to parse the provider feeds. Header-only, so it adds
# nothing to the runtime image.
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.11.3
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

find_package(Threads REQUIRED)

# OpenSSL libcrypto — AES-256-GCM for decrypting enc:v1: config values (SecretCodec-compatible).
find_package(OpenSSL REQUIRED)

# SQLite3 — read-only day-key store for the PATCH write surface (DayKeyStore). System library via
# CMake's built-in FindSQLite3 module (libsqlite3-dev at build time, libsqlite3-0 at runtime).
find_package(SQLite3 REQUIRED)

# Project version is surfaced by GET /health, generated into a header from PROJECT_VERSION.
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/src/version.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/generated/version.hpp
  @ONLY
)

# --- Core library (config + proxy) so it can be unit-tested apart from main() --
add_library(cproxy_core STATIC
  src/account_mirror_store.cpp
  src/breaker.cpp
  src/cloud_range_refresh.cpp
  src/cloud_range_store.cpp
  src/config.cpp
  src/day_key_store.cpp
  src/dotenv.cpp
  src/clock_offset.cpp
  src/jwt_verifier.cpp
  src/log.cpp
  src/proxy.cpp
  src/rabbit_event_consumer.cpp
  src/secret_codec.cpp
  src/user_prime_store.cpp
)
target_include_directories(cproxy_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}/generated
)
# OpenSSL::SSL joins libcrypto now that the refresher fetches provider feeds over HTTPS.
target_link_libraries(cproxy_core PUBLIC
  httplib::httplib Threads::Threads OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3
  nlohmann_json::nlohmann_json)
target_compile_options(cproxy_core PRIVATE -Wall -Wextra)

# --- Service executable -------------------------------------------------------
add_executable(cproxy src/main.cpp)
target_link_libraries(cproxy PRIVATE cproxy_core)

# --- Tests --------------------------------------------------------------------
enable_testing()
add_executable(config_test tests/config_test.cpp)
target_link_libraries(config_test PRIVATE cproxy_core)
add_test(NAME config_test COMMAND config_test)

add_executable(secret_codec_test tests/secret_codec_test.cpp)
target_link_libraries(secret_codec_test PRIVATE cproxy_core)
add_test(NAME secret_codec_test COMMAND secret_codec_test)

add_executable(proxy_test tests/proxy_test.cpp)
target_link_libraries(proxy_test PRIVATE cproxy_core)
add_test(NAME proxy_test COMMAND proxy_test)

add_executable(breaker_test tests/breaker_test.cpp)
target_link_libraries(breaker_test PRIVATE cproxy_core)
add_test(NAME breaker_test COMMAND breaker_test)

add_executable(day_key_store_test tests/day_key_store_test.cpp)
target_link_libraries(day_key_store_test PRIVATE cproxy_core)
add_test(NAME day_key_store_test COMMAND day_key_store_test)

add_executable(cloud_range_store_test tests/cloud_range_store_test.cpp)
target_link_libraries(cloud_range_store_test PRIVATE cproxy_core)
add_test(NAME cloud_range_store_test COMMAND cloud_range_store_test)

add_executable(account_mirror_store_test tests/account_mirror_store_test.cpp)
target_link_libraries(account_mirror_store_test PRIVATE cproxy_core)
add_test(NAME account_mirror_store_test COMMAND account_mirror_store_test)

add_executable(jwt_verifier_test tests/jwt_verifier_test.cpp)
target_link_libraries(jwt_verifier_test PRIVATE cproxy_core)
add_test(NAME jwt_verifier_test COMMAND jwt_verifier_test)

add_executable(user_prime_store_test tests/user_prime_store_test.cpp)
target_link_libraries(user_prime_store_test PRIVATE cproxy_core)
add_test(NAME user_prime_store_test COMMAND user_prime_store_test)

add_executable(clock_offset_test tests/clock_offset_test.cpp)
target_link_libraries(clock_offset_test PRIVATE cproxy_core)
add_test(NAME clock_offset_test COMMAND clock_offset_test)

