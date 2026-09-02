# CI step image for MilkTea's Woodpecker Storybook browser tests: greg-zone/bun-git
# with Chromium pre-installed by Playwright, so the test-storybook step no longer
# downloads the browser on every run.
#
# PLAYWRIGHT_BROWSERS_PATH is baked in and exported, so Playwright finds the
# browser at run time. The Chromium build is pinned to the Playwright version
# below, which must match the `playwright` version MilkTea resolves in bun.lock —
# on a mismatch Playwright errors asking for `playwright install` instead of
# silently downloading. Rebuild and bump both the pin and the tag whenever
# MilkTea bumps Playwright.
#
# Built locally on the Mini — never pushed to a registry. The Woodpecker agent
# shares the host Docker daemon, so a local tag is directly usable in
# .woodpecker.yml `image:` fields. Rebuild after a `docker system prune -a`
# (pipelines will fail with an image-pull error):
#
#   docker build -t greg-zone/milktea-storybook:1.4.0-pw1.58.2 ci/milktea-storybook
#
FROM greg-zone/bun-git:1.4.0

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

# Install the browsers the test-storybook step used to fetch per run, plus their
# system libraries, once at build time. Both chromium and chromium-headless-shell
# match what the pipeline installed before.
RUN bunx playwright@1.58.2 install --with-deps chromium chromium-headless-shell \
    && rm -rf /var/lib/apt/lists/*
