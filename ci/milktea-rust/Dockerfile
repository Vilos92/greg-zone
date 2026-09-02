# CI step image for MilkTea's Woodpecker Rust checks: rust 1.95.0 (matching
# MilkTea/rust-toolchain.toml) with rustfmt + clippy, plus the Tauri Linux
# system libraries clippy needs to compile the src-tauri crate. libasound2-dev
# is included on top of the gdex-rust set because MilkTea's cpal dependency
# links ALSA through pkg-config, and clippy compiles it.
#
# Built locally on the Mini — never pushed to a registry. The Woodpecker agent
# shares the host Docker daemon, so a local tag is directly usable in
# .woodpecker.yml `image:` fields. Rebuild after a `docker system prune -a`
# (pipelines will fail with an image-pull error) or to bump the rust version:
#
#   docker build -t greg-zone/milktea-rust:1.95.0 ci/milktea-rust
#
# Keep the tag in lockstep with the channel MilkTea pins in rust-toolchain.toml.
FROM rust:1.95.0-slim

RUN rustup component add rustfmt clippy \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        build-essential \
        curl \
        file \
        git \
        libasound2-dev \
        libayatana-appindicator3-dev \
        librsvg2-dev \
        libssl-dev \
        libwebkit2gtk-4.1-dev \
        libxdo-dev \
        pkg-config \
        wget \
    && rm -rf /var/lib/apt/lists/*
