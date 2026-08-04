# CI step image for Woodpecker pipelines: oven/bun plus git, which bun installs
# need (prepare scripts like scriptlancer's `vp config` shell out to git) and
# merge-base checks (fallow, wire-protocol gate) require.
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

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
