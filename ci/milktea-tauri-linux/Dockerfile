# Linux x86_64 release image for MilkTea's Tauri bundles. The Woodpecker
# Local-backend agent runs it through Docker Desktop with --platform linux/amd64.
# Ubuntu is required because Tauri fully supports GStreamer AppImage bundling
# only on Ubuntu build systems. Build locally on the Mini; never push it:
#
#   docker build --platform linux/amd64 \
#     -t greg-zone/milktea-tauri-linux:1.95.0-bun1.4.0 \
#     ci/milktea-tauri-linux
#
# Rebuild after a Docker image prune or when the pinned Bun, Node, or Rust
# version changes.
FROM oven/bun:1.4.0 AS bun
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG NODE_VERSION=24.14.1
ARG RUST_VERSION=1.95.0
ARG LINUXDEPLOY_URL=https://github.com/tauri-apps/binary-releases/releases/download/linuxdeploy/linuxdeploy-x86_64.AppImage
ARG LINUXDEPLOY_SHA256=e762bea85c8eb0d4b3508d46e5c1f037f717d0f9303ae3b4aafc8b04991fa1ef
ARG LINUXDEPLOY_SQUASHFS_OFFSET=193728

ENV APPIMAGE_EXTRACT_AND_RUN=1
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:${PATH}

COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY linuxdeploy-wrapper.c /tmp/linuxdeploy-wrapper.c

RUN ln -s /usr/local/bin/bun /usr/local/bin/bunx \
    && test "$(dpkg --print-architecture)" = amd64 \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        file \
        git \
        gstreamer1.0-plugins-bad \
        gstreamer1.0-plugins-base \
        gstreamer1.0-plugins-good \
        gstreamer1.0-tools \
        libayatana-appindicator3-dev \
        libgstreamer-plugins-base1.0-dev \
        libgstreamer1.0-dev \
        librsvg2-dev \
        libssl-dev \
        libwebkit2gtk-4.1-dev \
        libxdo-dev \
        patchelf \
        pkg-config \
        squashfs-tools \
        wget \
        xz-utils \
        zsync \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain "${RUST_VERSION}" \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      | tar -xJ -C /usr/local --strip-components=1

# Docker BuildKit cannot execute an amd64 AppImage while building through
# Docker Desktop's arm64 emulation. Extracting it as SquashFS avoids that nested
# runtime, and the ELF wrapper safely absorbs Tauri's AppImage header patch.
RUN curl -fsSL "${LINUXDEPLOY_URL}" -o /tmp/linuxdeploy.AppImage \
    && echo "${LINUXDEPLOY_SHA256}  /tmp/linuxdeploy.AppImage" | sha256sum -c - \
    && unsquashfs -quiet -offset "${LINUXDEPLOY_SQUASHFS_OFFSET}" -dest /opt/linuxdeploy /tmp/linuxdeploy.AppImage \
    && cc -O2 -s -o /usr/local/bin/linuxdeploy-wrapper /tmp/linuxdeploy-wrapper.c \
    && rm -f /tmp/linuxdeploy.AppImage /tmp/linuxdeploy-wrapper.c \
    && bun --version \
    && node --version \
    && rustc --version
