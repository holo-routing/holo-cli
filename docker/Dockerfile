# Build image
# ==============================================================================

FROM ghcr.io/rust-lang/rust:nightly-bookworm AS build

RUN apt-get update && \
    apt-get install -y build-essential \
    cmake \
    libpcre2-dev \
    protobuf-compiler

ARG BUILD_PROFILE=release

WORKDIR /usr/src/holo
COPY . .
RUN cargo build --profile $BUILD_PROFILE

# Final base
# ==============================================================================

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y less \
  && rm -rf /var/lib/apt/lists/*

ARG BUILD_PROFILE=release
COPY --from=build /usr/src/holo/target/$BUILD_PROFILE/holo-cli /usr/local/sbin/

ENV RUST_BACKTRACE=1
ENTRYPOINT ["holo-cli"]
