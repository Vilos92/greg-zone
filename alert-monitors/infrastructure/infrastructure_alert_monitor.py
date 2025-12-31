#!/usr/bin/env python3
"""
Infrastructure Alert Monitor with Redis persistence
Monitors the monitoring infrastructure: loki, prometheus, grafana, alertmanager, etc.
Handles infrastructure service health monitoring.
"""

import time
import requests
import re
from datetime import datetime
from typing import Dict, Any, List
import logging

from shared.base_alert_monitor import BaseAlertMonitor
from shared.utils import format_nginx_timestamp

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class InfrastructureAlertMonitor(BaseAlertMonitor):
    """Alert monitor for infrastructure services with Redis persistence."""

    def __init__(self):
        """Initialize the infrastructure alert monitor with Redis."""
        alert_configs = [
            # Public service health monitoring
            {
                "name": "copyparty_public_health",
                "service": "infra",
                "check_type": "url_health_check",
                "urls": ["https://copyparty.greglinscheid.com"],
                "alert_type": "service_health_change",
                "discord_title": "📁 Copyparty Service Up",
                "discord_message": "Copyparty is now {state}!\n\n🌐 **URL:** https://copyparty.greglinscheid.com",
                "discord_title_offline": "📁 Copyparty Service Down",
                "discord_message_offline": "Copyparty is now offline.\n\n🌐 **URL:** https://copyparty.greglinscheid.com\n\n📝 **Description:** Copyparty file sharing service has stopped responding",
                "color_online": 0x00FF00,
                "color_offline": 0xFF0000,
                "track_state": True,
                "state_key": "copyparty_public",
            },
            {
                "name": "freshrss_public_health",
                "service": "infra",
                "check_type": "url_health_check",
                "urls": ["https://freshrss.greglinscheid.com"],
                "alert_type": "service_health_change",
                "discord_title": "📰 FreshRSS Service Up",
                "discord_message": "FreshRSS is now {state}!\n\n🌐 **URL:** https://freshrss.greglinscheid.com",
                "discord_title_offline": "📰 FreshRSS Service Down",
                "discord_message_offline": "FreshRSS is now offline.\n\n🌐 **URL:** https://freshrss.greglinscheid.com\n\n📝 **Description:** FreshRSS feed reader service has stopped responding",
                "color_online": 0x00FF00,
                "color_offline": 0xFF0000,
                "track_state": True,
                "state_key": "freshrss_public",
            },
        ]

        super().__init__(alert_configs, "infrastructure")

        # Initialize server states for infrastructure monitoring
        self.server_states = self.redis_client.get_server_states()

    def check_url_health(self, url: str, timeout: int = 10) -> bool:
        """Check if a URL is responding with a healthy status code."""
        try:
            health_token = self.generate_health_check_token()
            headers = {
                "X-Health-Check": f"alert-monitor-{health_token}",
                "User-Agent": "alert-monitor-health-check/1.0",
            }
            response = requests.head(
                url, timeout=timeout, allow_redirects=True, headers=headers
            )

            return response.status_code < 400
        except Exception as e:
            logger.error(f"Error checking URL health for {url}: {e}")
            return False

    def run(self):
        """Main monitoring loop for infrastructure services."""
        logger.info("Starting Infrastructure Alert Monitor with Redis persistence")

        while True:
            try:
                current_time = datetime.now()
                logger.info(f"Checking infrastructure services at {current_time}")

                # Process each alert configuration
                for config in self.alert_configs:
                    if config.get("check_type") == "url_health_check":
                        self.process_url_health_check(config)
                    elif config.get("alert_type") == "bot_blocked":
                        # Query Loki for 403 responses
                        logs = self.query_loki(config["query"])
                        if logs:
                            self.process_bot_blocked_alert(config, logs)

                # Update last check time and save state
                self.last_check_time = current_time
                self.save_state()

                # Wait for next check
                time.sleep(self.check_interval)

            except KeyboardInterrupt:
                logger.info("Infrastructure Alert Monitor stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in Infrastructure Alert Monitor: {e}")
                time.sleep(self.check_interval)

    def process_url_health_check(self, config: Dict[str, Any]):
        """Process URL health checks for infrastructure services."""
        urls = config.get("urls", [])
        if not urls:
            return

        # Check all URLs
        all_healthy = True
        for url in urls:
            if not self.check_url_health(url):
                all_healthy = False
                break

        # Determine current state
        current_state = "online" if all_healthy else "offline"
        state_key = config.get("state_key", config["name"])

        # Check if state changed
        previous_state = self.server_states.get(state_key, "unknown")
        if previous_state == current_state:
            logger.info(
                f"Infrastructure service health unchanged for {state_key}: {current_state}"
            )
            return

        # State changed - send alert
        logger.info(
            f"Infrastructure service health changed for {state_key}: {previous_state} -> {current_state}"
        )

        # Send alert
        self.send_service_health_alert(config, current_state)

        # Update state
        self.server_states[state_key] = current_state

    def send_service_health_alert(self, config: Dict[str, Any], state: str):
        """Send service health change alert."""
        try:
            color = config.get(f"color_{state}", config.get("color", 0x00FF00))

            # Use offline-specific messages if available and state is offline
            if state == "offline" and "discord_title_offline" in config:
                discord_title = config["discord_title_offline"]
                discord_message = config["discord_message_offline"]
            else:
                discord_title = config["discord_title"]
                discord_message = config["discord_message"].format(state=state)

            payload = {
                "alerts": [
                    {
                        "status": "firing",
                        "labels": {
                            "service": config["service"],
                            "alert_type": config["alert_type"],
                            "state": state,
                        },
                        "annotations": {
                            "discord_title": discord_title,
                            "discord_message": discord_message,
                        },
                    }
                ],
                "color": color,
            }

            self.send_webhook(payload)
            logger.info(
                f"Sent infrastructure state alert: {config.get('state_key', config['name'])} {state}"
            )

        except Exception as e:
            logger.error(f"Error sending infrastructure service health alert: {e}")

    def save_state(self):
        """Save infrastructure monitor state to Redis."""
        try:
            # Call parent save_state first
            super().save_state()

            # Save server states
            self.redis_client.set_server_states(self.server_states)

        except Exception as e:
            logger.error(f"Error saving infrastructure state: {e}")

    def process_bot_blocked_alert(self, config: Dict[str, Any], logs: List[Dict]):
        """Process bot blocked alerts (403 responses from nginx)."""
        pattern = re.compile(config["pattern"])
        ip_field = config.get("ip_field", "forwarded_for")
        current_time = datetime.now()

        for log in logs:
            match = pattern.search(log["message"])
            if match:
                match_data = match.groupdict()
                ip_address = match_data.get(ip_field) or match_data.get("remote_addr")
                user_agent = match_data.get("http_user_agent", "Unknown")

                if not ip_address or ip_address == "-":
                    continue

                # Skip legitimate health check requests
                if "alert-monitor-health-check" in user_agent:
                    continue

                # Always alert on bot 403s (nginx bot detection is reliable)
                logger.info(
                    f"Bot blocked: {ip_address} with user agent: {user_agent[:50]}..."
                )
                self.send_bot_blocked_alert(
                    config, match_data, ip_address, current_time
                )

    def send_bot_blocked_alert(
        self,
        config: Dict[str, Any],
        match_data: Dict,
        ip_address: str,
        current_time: datetime,
    ):
        """Send alert for bot blocked (403 response) and track IP."""
        try:
            # Determine client IP and location
            client_ip = match_data.get("forwarded_for") or ip_address
            cf_country = match_data.get("cf_country", "")
            if cf_country and cf_country != "":
                location = cf_country
            else:
                location = "Unknown"

            # Track IP in Redis (similar to services monitor)
            ip_key = f"{config['service']}:{client_ip}"
            existing_ip_data = self.redis_client.get_ip_data(ip_key)

            # Use cached country if available, otherwise use Cloudflare country
            if (
                existing_ip_data
                and existing_ip_data.get("country")
                and existing_ip_data.get("country") not in ["Unknown", None, ""]
            ):
                location = existing_ip_data.get("country")
            elif cf_country and cf_country != "":
                location = cf_country

            # Update IP in Redis with current timestamp and location
            self.redis_client.update_ip(ip_key, current_time, location)

            host = match_data.get("host", "Unknown")
            user_agent = match_data.get("http_user_agent", "Unknown")

            # Use the detailed message template from config
            discord_message = config["discord_message"].format(
                client_ip=client_ip,
                location=location,
                formatted_time=format_nginx_timestamp(
                    match_data.get("time_local", "Recent")
                ),
                host=host,
                method=match_data.get("method", "Unknown"),
                request_uri=match_data.get("request_uri", "Unknown"),
                protocol=match_data.get("protocol", "HTTP/1.1"),
                http_user_agent=user_agent,
                http_referer=match_data.get("http_referer", "-"),
                cf_ray=match_data.get("cf_ray", "-"),
            )

            payload = {
                "alerts": [
                    {
                        "status": "firing",
                        "labels": {
                            "service": config["service"],
                            "alert_type": config["alert_type"],
                            "ip_address": ip_address,
                        },
                        "annotations": {
                            "discord_title": config["discord_title"],
                            "discord_message": discord_message,
                        },
                    }
                ],
                "color": config["color"],
            }

            self.send_webhook(payload)
            logger.info(
                f"Sent bot blocked alert: {config['service']} - {ip_address} (IP tracked in Redis)"
            )

        except Exception as e:
            logger.error(f"Error sending bot blocked alert: {e}")


if __name__ == "__main__":
    monitor = InfrastructureAlertMonitor()
    monitor.run()
