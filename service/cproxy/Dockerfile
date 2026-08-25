# syntax=docker/dockerfile:1
#
# cproxy — C++23 reverse proxy. Multi-stage build on Debian 13 ("trixie").
#
# NOTE: base images are referenced by tag here for readability. For reproducible,
# tamper-resistant releases, pin both to a digest (docker inspect --format
# '{{index .RepoDigests 0}}' debian:trixie) once first pulled, matching the sibling
# services' convention.

# ---- build stage ------------------------------------------------------------
FROM debian:trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake git ca-certificates libssl-dev libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src
COPY tests ./tests

# Configure + build (Release), then run the unit tests as part of the image build so a
# broken build never ships.
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --parallel \
 && ctest --test-dir build --output-on-failure

# ---- runtime stage ----------------------------------------------------------
FROM debian:trixie-slim
# wget for the HEALTHCHECK; openssl pulls libcrypto (runtime dep of the secret codec); libsqlite3-0
# is the day-key store's runtime dependency; ca-certificates for good measure. libstdc++6 ships in
# the base.
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates openssl libsqlite3-0 \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user (uid 10001), matching the other services. Pre-create the log directory
# owned by that user so the container writes logs whether or not a volume is mounted over it (a bind
# mount from the host is expected in production, owned by the same uid).
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home app \
 && mkdir -p /var/log/cproxy \
 && chown -R 10001:10001 /var/log/cproxy

COPY --from=build /src/build/cproxy /usr/local/bin/cproxy

# Rolling logs go here by default; mount a persistent volume at this path in production.
ENV CPROXY_LOG_DIR=/var/log/cproxy

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/cproxy"]
