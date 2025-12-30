# GregZone Infrastructure

Personal infrastructure setup using Docker Compose, including:

- **Services**: copyparty, FreshRSS, Kiwix, Transmission, Minecraft
- **Monitoring**: Prometheus, Grafana, Loki, Promtail, Alertmanager, Node Exporter, cAdvisor, Docker Stats Exporter, MC Monitor
- **Networking**: Tailscale, Cloudflare tunnels, Nginx reverse proxies
- **Alerting**: Custom alert monitors with Discord webhooks
- **Supporting**: Redis, Redis Commander, Playit, Minecraft Backup

## Quick Start

```bash
# Start all services
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
  - `/Volumes/Wokyis M.2 SSD - Storage/Vaults` - GregZone Vault + Hobby Vault (required for copyparty, freshrss, transmission, minecraft).
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

### Public Access (via Cloudflare)

- Copyparty: https://copyparty.greglinscheid.com
- FreshRSS: https://freshrss.greglinscheid.com
- Kiwix: https://kiwix.greglinscheid.com

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
- `nginx/` - Nginx reverse proxy configs (Tailscale and Cloudflare).
- `prometheus/` - Prometheus configuration.
- `promtail/` - Promtail log shipping config.
