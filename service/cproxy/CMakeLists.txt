cmake_minimum_required(VERSION 3.20)
project(cproxy VERSION 0.5.1 LANGUAGES CXX)

# C++23 as requested; no compiler extensions so the code stays portable.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# --- HTTP engine: cpp-httplib (header-only server + client) -------------------
# Pinned to a release tag for reproducible builds. Keep the optional TLS/zlib/brotli
# integrations OFF: cproxy speaks plain HTTP to the internal upstreams, so a lean
# binary with no libssl/libz runtime dependency is preferred. TLS termination for the
# public edge is a fronting concern (added later), not this process's job yet.
include(FetchContent)
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE   OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG        v0.15.3
)
FetchContent_MakeAvailable(httplib)

find_package(Threads REQUIRED)

# OpenSSL libcrypto — AES-256-GCM for decrypting enc:v1: config values (SecretCodec-compatible).
find_package(OpenSSL REQUIRED)

# Project version is surfaced by GET /health, generated into a header from PROJECT_VERSION.
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/src/version.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/generated/version.hpp
  @ONLY
)

# --- Core library (config + proxy) so it can be unit-tested apart from main() --
add_library(cproxy_core STATIC
  src/breaker.cpp
  src/config.cpp
  src/dotenv.cpp
  src/log.cpp
  src/proxy.cpp
  src/secret_codec.cpp
)
target_include_directories(cproxy_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_link_libraries(cproxy_core PUBLIC httplib::httplib Threads::Threads OpenSSL::Crypto)
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
