# CI step image for gdex's Woodpecker Rust checks: rust 1.95.0 (matching
# gdex/rust-toolchain.toml) with rustfmt + clippy, plus the Tauri Linux system
# libraries clippy needs to compile the src-tauri crate, and git + pkg-config.
#
# Built locally on the Mini — never pushed to a registry. The Woodpecker agent
# shares the host Docker daemon, so a local tag is directly usable in
# .woodpecker.yml `image:` fields. Rebuild after a `docker system prune -a`
# (pipelines will fail with an image-pull error) or to bump the rust version:
#
#   docker build -t greg-zone/gdex-rust:1.95.0 ci/gdex-rust
#
# Keep the tag in lockstep with the channel gdex pins in rust-toolchain.toml.
FROM rust:1.95.0-slim

RUN rustup component add rustfmt clippy \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        git \
        pkg-config \
        build-essential \
        curl \
        wget \
        file \
        libwebkit2gtk-4.1-dev \
        libxdo-dev \
        libssl-dev \
        libayatana-appindicator3-dev \
        librsvg2-dev \
    && rm -rf /var/lib/apt/lists/*
