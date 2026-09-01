# CI step image for s3-amoled's host and ESP32-S3 Rust checks. It combines
# Rust 1.95.0 (matching s3-amoled/rust-toolchain.toml), rustfmt, Clippy, the
# Slint Linux libraries, and the pinned Espressif Xtensa toolchain.
#
# Built natively on the Mini and never pushed to a registry. The Woodpecker
# agent shares the host Docker daemon, so a local tag is directly usable in
# .woodpecker.yml `image:` fields. Rebuild after a Docker image prune or when
# the pinned host Rust, espup, or Xtensa Rust version changes:
#
#   docker build \
#     -t greg-zone/s3-amoled-rust:1.95.0-espup0.17.1-xtensa1.97.0.0 \
#     ci/s3-amoled-rust
#
# Keep the host Rust version aligned with s3-amoled/rust-toolchain.toml and the
# Xtensa Rust version aligned with the toolchain used for local firmware checks.
FROM rust:1.95.0-slim-bookworm

ARG ESPUP_VERSION=0.17.1
ARG ESPUP_SHA256=2c2275cc937f33f64d65bed4338aa4216f2c70c9dfe5e563b9942cd936088b0c
ARG XTENSA_RUST_VERSION=1.97.0.0

RUN test "$(dpkg --print-architecture)" = arm64 \
    && rustup component add rustfmt clippy \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        libfontconfig1-dev \
        libx11-dev \
        libx11-xcb-dev \
        libxcb1-dev \
        libxcursor-dev \
        libxkbcommon-dev \
        libxkbcommon-x11-dev \
        pkg-config \
        xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL \
        "https://github.com/esp-rs/espup/releases/download/v${ESPUP_VERSION}/espup-aarch64-unknown-linux-gnu" \
        -o /usr/local/bin/espup \
    && echo "${ESPUP_SHA256}  /usr/local/bin/espup" | sha256sum --check --strict \
    && chmod +x /usr/local/bin/espup \
    && mkdir -p /opt/esp \
    && espup install \
        --default-host aarch64-unknown-linux-gnu \
        --export-file /opt/esp/export-esp.sh \
        --targets esp32s3 \
        --toolchain-version "${XTENSA_RUST_VERSION}" \
    && . /opt/esp/export-esp.sh \
    && rustc +esp --version
