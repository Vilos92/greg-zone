# GregZone Infrastructure

Personal infrastructure setup using Docker Compose, including:

- **Services**: copyparty, FreshRSS, Kiwix, Transmission, Minecraft (profile-gated), Hermes Agent
- **Monitoring**: Prometheus, Grafana, Loki, Promtail, Alertmanager, Node Exporter, cAdvisor, Docker Stats Exporter, MC Monitor (profile-gated)
- **Networking**: Tailscale, Cloudflare tunnels, Nginx reverse proxies
- **Alerting**: Custom alert monitors with Discord webhooks
- **Supporting**: Redis, Redis Commander, Playit (profile-gated), Minecraft Backup (profile-gated)
- **CI**: Woodpecker CI (server + agent, per-repo opt-in for any GitHub repo)

## Minecraft services are profile-gated

The five Minecraft services — `minecraft`, `minecraft-backup`, `playit`,
`mc-monitor`, `minecraft-alert-monitor` — carry `profiles: ['minecraft']` in
`docker-compose.yml`, so a plain `./docker-services.sh up` skips them.

**Do not bring these up unless Greg explicitly asks for Minecraft.** The gate is
deliberate — a missing minecraft container, an empty `minecraft-monitoring`
dashboard, and the commented-out `minecraft-monitor` scrape job are the intended
state, not something to repair. Don't add `COMPOSE_PROFILES=minecraft` to a
command on your own initiative, and don't delete a `profiles:` key to un-gate a
service.

Definitions and world data stay fully intact, so returning is one command:

```bash
COMPOSE_PROFILES=minecraft ./docker-services.sh up
```

This needs no change to `docker-services.sh` — Compose reads `COMPOSE_PROFILES`
natively. Also uncomment the `minecraft-monitor` scrape job in
`prometheus/prometheus.yml` and `./docker-services.sh restart prometheus`, or
its Grafana dashboard stays empty.

## Quick Start

```bash
# Start all services (Minecraft excluded — see profile note above)
./docker-services.sh up

# Check prerequisites
./docker-services.sh check

# View logs
./docker-services.sh logs -f

# Show access URLs
./docker-services.sh access
```

## Requirements

- Docker and Docker Compose.
- External drives mounted:
  - `/Volumes/T7/Vaults` - Main data vaults (required for copyparty, kiwix).
  - `/Volumes/Wokyis M.2 SSD - Storage/Vaults` - GregZone Vault, Hobby Vault, Cloud Vault (required for copyparty, freshrss, transmission, minecraft).
- Environment variables in `.env` file (see AGENTS.md for full list).
- Tailscale for private network access.

## Available Commands

See `./docker-services.sh help` for all available commands:

- `up` - Start all services
- `down` - Stop all services
- `restart` - Restart all services
- `ps` - Show service status
- `logs [service]` - Show logs (add `-f` to follow)
- `pull` - Pull latest images
- `build` - Build services
- `update` - Pull latest images and restart
- `check` - Check prerequisites
- `access` - Show service access information
- `monitoring` - Show monitoring setup information

## Service Access

### Tailscale Access (Private Network)

- Main Dashboard: http://greg-zone (port 80)
- Copyparty: http://greg-zone:9001
- FreshRSS: http://greg-zone:9002
- Kiwix: http://greg-zone:9003
- Transmission: http://greg-zone:9004
- Prometheus: http://greg-zone:9005
- Grafana: http://greg-zone:9006
- cAdvisor: http://greg-zone:9007
- Redis Commander: http://greg-zone:8084
- Prowlarr: http://greg-zone:9009
- Hermes: http://greg-zone:9010
- Woodpecker: http://greg-zone:9011

### Public Access (via Cloudflare)

- Copyparty: https://copyparty.greglinscheid.com
- FreshRSS: https://freshrss.greglinscheid.com
- Kiwix: https://kiwix.greglinscheid.com
- Woodpecker webhooks: https://woodpecker.greglinscheid.com (GitHub `/api/hook` only; all other paths refused)

## Structure

- `docker-compose.yml` - Main service definitions.
- `docker-services.sh` - Management script.
- `alert-monitors/` - Custom alert monitoring services (services, infrastructure, minecraft monitors).
- `alertmanager/` - Alertmanager configuration.
- `copyparty/` - File sharing service config.
- `discord-webhook/` - Discord webhook multiplexer service.
- `docker-stats-exporter/` - Docker stats exporter for Prometheus.
- `grafana/` - Grafana dashboards and provisioning.
- `loki/` - Loki log aggregation config.
- `minecraft/` - Minecraft server and backup configuration.
- `ci/` - Locally built images for Woodpecker pipeline steps (e.g. `bun-git`; never pushed to a registry, rebuild instructions in each Dockerfile).
- `nginx/` - Nginx reverse proxy configs (Tailscale and Cloudflare).
- `prometheus/` - Prometheus configuration.
- `promtail/` - Promtail log shipping config.
