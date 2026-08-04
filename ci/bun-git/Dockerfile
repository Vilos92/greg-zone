# CI step image for Woodpecker pipelines: oven/bun plus git, which bun installs
# need (prepare scripts like scriptlancer's `vp config` shell out to git) and
# merge-base checks (fallow, wire-protocol gate) require, plus a real Node.js.
# Real Node matters because Bun's bundled node shim cannot resolve some
# packages' conditional exports (vilos92.com's `vp test` hits this via zod);
# /usr/local/bin/node shadows the shim.
#
# Built locally on the Mini — never pushed to a registry. The Woodpecker agent
# shares the host Docker daemon, so a local tag is directly usable in
# .woodpecker.yml `image:` fields. Rebuild after a `docker system prune -a`
# (pipelines will fail with an image-pull error) or to bump the bun version:
#
#   docker build -t greg-zone/bun-git:1.3.14 ci/bun-git
#
# Keep the tag in lockstep with the bun version repos pin via `packageManager`.
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
