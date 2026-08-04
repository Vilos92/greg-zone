# CI step image for the dotfiles Woodpecker pipeline: oven/bun (bunx prettier)
# plus git (submodule init), shellcheck, and ruff (static binary from the
# official image).
#
# Built locally on the Mini — never pushed to a registry. Rebuild after a
# `docker system prune -a` (pipelines will fail with an image-pull error):
#
#   docker build -t greg-zone/dotfiles-lint:1 ci/dotfiles-lint
FROM ghcr.io/astral-sh/ruff:latest AS ruff

FROM oven/bun:1.3.14

COPY --from=ruff /ruff /usr/local/bin/ruff

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends git ca-certificates shellcheck \
    && rm -rf /var/lib/apt/lists/*
