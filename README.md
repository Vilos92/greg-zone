# GregZone Infrastructure

Personal infrastructure setup using Docker Compose, including:

- **Services**: copyparty, FreshRSS, Kiwix, Transmission
- **Monitoring**: Prometheus, Grafana, Loki, Promtail
- **Networking**: Tailscale, Cloudflare tunnels
- **Alerting**: Custom alert monitors with Discord webhooks

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

- Docker and Docker Compose
- External drives mounted:
  - `/Volumes/T7` - Main data hub
  - `/Volumes/Wokyis M.2 SSD - Storage` - GregZone Vault
- Environment variables in `.env` file
- Tailscale for private network access

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
- Main Dashboard: http://greg-zone
- Grafana: http://greg-zone:9006
- Copyparty: http://greg-zone:9001
- FreshRSS: http://greg-zone:9002
- Kiwix: http://greg-zone:9003
- Transmission: http://greg-zone:9004

### Public Access (via Cloudflare)
- Copyparty: https://copyparty.greglinscheid.com
- FreshRSS: https://freshrss.greglinscheid.com
- Kiwix: https://kiwix.greglinscheid.com

## Structure

- `docker-compose.yml` - Main service definitions
- `docker-services.sh` - Management script
- `alert-monitors/` - Custom alert monitoring services
- `copyparty/` - File sharing service config
- `grafana/` - Grafana dashboards and provisioning
- `nginx/` - Nginx reverse proxy configs
- `prometheus/` - Prometheus configuration
- `loki/` - Loki log aggregation config
- `promtail/` - Promtail log shipping config

