# CI step image for Woodpecker pipelines: oven/bun plus git, which bun installs
# need (prepare scripts like scriptlancer's `vp config` shell out to git) and
# merge-base checks (fallow, wire-protocol gate) require, plus a real Node.js.
# Real Node matters because Bun's bundled node shim cannot resolve some
# packages' conditional exports (vilos92.com's `vp test` hits this via zod);
# /usr/local/bin/node shadows the shim.
#
# It also carries the linux-arm64 WebTransport native addon in
# /opt/webtransport-prebuilds — see the builder stage below.
#
# Built locally on the Mini — never pushed to a registry. The Woodpecker agent
# shares the host Docker daemon, so a local tag is directly usable in
# .woodpecker.yml `image:` fields. Rebuild after a `docker system prune -a`
# (pipelines will fail with an image-pull error) or to bump any version it pins:
#
#   docker build -t greg-zone/bun-git:1.3.14-wt0.3.0 ci/bun-git
#
# Keep the bun half of the tag in lockstep with the bun version repos pin via
# `packageManager`, and the wt half with the `@webtransport-bun/webtransport`
# version they install.

# `@webtransport-bun/webtransport` publishes exactly one Linux prebuilt addon,
# linux-x64-gnu, so an arm64 host has none and every consuming repo's tests fail
# at `require()` time. This stage builds it. The crate is portable Rust, and
# napi-rs's CLI copies the release cdylib to
# `<binaryName>.<platform>-<arch>-<abi>.node` and nothing else, so a cargo build
# plus the rename is the artifact upstream would have published.
#
# The commit pin has to match the npm version consuming repos install: the addon
# and the JS that loads it come from one release, so bumping the dependency means
# rebuilding this image in the same change. `--locked` extends that pin to the
# transitive Rust graph, which earns its keep here because this is the one stage
# that compiles third-party code on the host.
#
# The rust tag is exact so the toolchain building the addon moves on our
# schedule rather than the floating tag's.
#
# This stage retires the day upstream publishes a linux-arm64 prebuild: consumers
# drop their copy step and `bun install` supplies the addon itself.
FROM rust:1.97.1-bookworm AS webtransport-builder

ARG WEBTRANSPORT_REPO=https://github.com/vmeansdev/webtransport-bun.git
ARG WEBTRANSPORT_TAG=v0.3.0
ARG WEBTRANSPORT_COMMIT=131dc47676f30edb61c172dc47a412150269029d

# An amd64 host already has the published prebuild, so this stage refuses to run
# there rather than emit an x64 binary under an arm64 name.
RUN test "$(dpkg --print-architecture)" = arm64 \
    && git clone --depth 1 --branch "$WEBTRANSPORT_TAG" "$WEBTRANSPORT_REPO" /src \
    && test "$(git -C /src rev-parse HEAD)" = "$WEBTRANSPORT_COMMIT" \
    && cargo build --locked --release --manifest-path /src/crates/native/Cargo.toml \
    && mkdir -p /opt/webtransport-prebuilds \
    && cp /src/target/release/libnative.so \
       /opt/webtransport-prebuilds/webtransport-native.linux-arm64-gnu.node

FROM oven/bun:1.3.14

ARG NODE_VERSION=24.14.1

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends git ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in arm64) narch=arm64 ;; amd64) narch=x64 ;; *) echo "unsupported arch $arch" && exit 1 ;; esac \
    && mkdir -p /usr/local/node \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${narch}.tar.xz" \
       | tar -xJ -C /usr/local/node --strip-components=1 \
    && ln -sf /usr/local/node/bin/node /usr/local/bin/node \
    && ln -sf /usr/local/node/bin/npm /usr/local/bin/npm \
    && ln -sf /usr/local/node/bin/npx /usr/local/bin/npx \
    && node --version

# Last, so re-pinning the addon reuses the Node layer above.
COPY --from=webtransport-builder /opt/webtransport-prebuilds /opt/webtransport-prebuilds
