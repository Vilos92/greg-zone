# Native macOS GitHub Actions runners (scriptlancer)

Linux-in-Docker on Apple Silicon was a dead end for `@webtransport-bun` (no usable
`linux-arm64` prebuild; `linux/amd64` under Rosetta failed to load the napi addon).
Runners live **on the Mac host** so Bun loads `darwin-arm64.node`.

Workflows use:

```yaml
runs-on: [self-hosted, macOS, ARM64, greg-zone]
```

## Setup (once on the Mini)

1. Put `GITHUB_RUNNER_ACCESS_TOKEN` in `../.env` (same fine-grained PAT as before:
   Administration read/write on `Vilos92/scriptlancer`).
2. From this directory:

```bash
./setup.sh          # installs 6 runners under ~/actions-runners/scriptlancer-{1..6}
./setup.sh --count 3   # optional: fewer parallel slots
```

3. Confirm Idle runners under the repo → Settings → Actions → Runners.
4. Tear down the old compose Linux runners if they are still up:

```bash
cd ..
docker-compose -f docker-compose.yml rm -sf \
  github-runner-1 github-runner-2 github-runner-3 \
  github-runner-4 github-runner-5 github-runner-6
```

(Those services are removed from `docker-compose.yml`; this only clears leftovers.)

## Ops

```bash
./setup.sh --status    # launchd state
./setup.sh --stop      # stop all
./setup.sh --start     # start all
./setup.sh --remove    # deregister + uninstall services + delete dirs
```

Each instance is a launchd service (`actions.runner.*`). They share labels so GitHub
can schedule up to N jobs in parallel on this Mini.
