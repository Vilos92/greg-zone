#!/usr/bin/env python3
"""
Minecraft Alert Monitor with Redis persistence
Monitors Minecraft server health and player activity.
"""

import time
import requests
import re
from datetime import datetime
from typing import Dict, Any, List
import logging

from shared.base_alert_monitor import BaseAlertMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class MinecraftAlertMonitor(BaseAlertMonitor):
    """Alert monitor for Minecraft server with Redis persistence."""

    def __init__(self):
        """Initialize the Minecraft alert monitor with Redis."""
        alert_configs = [
            # Minecraft server health monitoring
            {
                "name": "minecraft_server_health",
                "service": "minecraft",
                "check_type": "health_check",
                "host": "minecraft",
                "port": 19132,
                "alert_type": "server_health_change",
                "discord_title": "🟢 Jordania Online",
                "discord_message": "🎮 **Server:** Jordania\n⏰ **Time:** {timestamp}",
                "discord_title_offline": "🔴 Jordania Offline",
                "discord_message_offline": "🎮 **Server:** Jordania\n📝 **Description:** Minecraft server has stopped responding",
                "color_online": 0x00FF00,
                "color_offline": 0xFF0000,
                "track_state": True,
                "state_key": "minecraft",
            },
            # Minecraft player activity monitoring
            {
                "name": "minecraft_player_activity",
                "service": "minecraft",
                "query": '{container_name="minecraft"} |~ "Player (connected|disconnected):"',
                "pattern": r"Player (?P<event_type>connected|disconnected): (?P<player_name>[^,]+), xuid: (?P<xuid>\d+)",
                "alert_type": "player_activity",
                "discord_title": "🎮 Player Activity",
                "discord_message": "👤 **{player_name}** {event_type} the server!\n**XUID:** `{xuid}`\n⏰ **Time:** {timestamp}",
                "color": 0x00FF00,
                "track_state": True,
            },
        ]

        super().__init__(alert_configs, "minecraft")

        # Initialize server states for Minecraft monitoring
        self.server_states = self.redis_client.get_server_states()

    def check_server_health(self, host: str, port: int) -> bool:
        """Override to use mc-monitor metrics endpoint for Minecraft health checks."""
        if host == "minecraft":
            try:
                response = requests.get("http://mc-monitor:8080/metrics", timeout=5)
                if response.status_code == 200:
                    # Check if minecraft_status_healthy metric exists and is 1
                    metrics_text = response.text
                    for line in metrics_text.split("\n"):
                        if line.startswith("minecraft_status_healthy") and "1" in line:
                            return True
                    return False
                else:
                    return False
            except Exception:
                return False
        else:
            # Fall back to parent implementation for other hosts
            return super().check_server_health(host, port)

    def process_player_activity_alert(self, config: Dict[str, Any], logs: List[Dict]):
        """Process player activity alerts (join/leave events)."""
        pattern = re.compile(config["pattern"])
        current_time = datetime.now()

        for log_entry in logs:
            try:
                # Parse the log message
                match = pattern.search(log_entry["message"])
                if not match:
                    continue

                match_data = match.groupdict()
                player_name = match_data.get("player_name")
                xuid = match_data.get("xuid")
                event_type_raw = match_data.get("event_type")

                if not player_name or not xuid or not event_type_raw:
                    continue

                # Store XUID to username mapping in Redis
                self.store_player_mapping(xuid, player_name, current_time)

                # Convert event type to user-friendly format
                if event_type_raw == "connected":
                    event_type = "joined"
                elif event_type_raw == "disconnected":
                    event_type = "left"
                else:
                    continue

                # No cooldown for player activity - we want to see all join/leave events

                # Format timestamp
                timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S UTC")

                # Send alert
                self.send_player_activity_alert(
                    config, match_data, event_type, timestamp
                )

                logger.info(
                    f"Player activity detected: {player_name} {event_type} the server"
                )

            except Exception as e:
                logger.error(f"Error processing player activity log: {e}")

    def send_player_activity_alert(
        self, config: Dict[str, Any], match_data: Dict, event_type: str, timestamp: str
    ):
        """Send alert for player activity."""
        try:
            # Use the detailed message template from config with actual log data
            discord_message = config["discord_message"].format(
                player_name=match_data.get("player_name", "Unknown"),
                event_type=event_type,
                xuid=match_data.get("xuid", "Unknown"),
                timestamp=timestamp,
            )

            # Choose color based on event type
            if event_type == "joined":
                color = 0x0099FF  # Blue for joining
            elif event_type == "left":
                color = 0xFFAA00  # Orange for leaving
            else:
                color = config["color"]  # Fallback to default

            payload = {
                "alerts": [
                    {
                        "status": "firing",
                        "labels": {
                            "service": config["service"],
                            "alert_type": config["alert_type"],
                            "player_name": match_data.get("player_name", "Unknown"),
                            "xuid": match_data.get("xuid", "Unknown"),
                            "event_type": event_type,
                        },
                        "annotations": {
                            "discord_title": config["discord_title"],
                            "discord_message": discord_message,
                        },
                    }
                ],
                "color": color,
            }

            self.send_webhook(payload)
            logger.info(
                f"Sent player activity alert: {match_data.get('player_name', 'Unknown')} {event_type}"
            )

        except Exception as e:
            logger.error(f"Error sending player activity alert: {e}")

    def run(self):
        """Main monitoring loop for Minecraft server."""
        logger.info("Starting Minecraft Alert Monitor with Redis persistence")

        while True:
            try:
                current_time = datetime.now()
                logger.info(f"Checking Minecraft server at {current_time}")

                # Process each alert configuration
                for config in self.alert_configs:
                    logger.info(
                        f"Processing config: {config['name']}, check_type: {config.get('check_type', 'None')}"
                    )
                    if config.get("check_type") == "health_check":
                        logger.info(f"Processing health check for {config['name']}")
                        self.process_server_health_check(config)
                    else:
                        logger.info(
                            f"Querying Loki for {config['name']}: {config['query']}"
                        )
                        # Query Loki for logs
                        logs = self.query_loki(config["query"])
                        logger.info(
                            f"Loki query returned {len(logs)} logs for {config['name']}"
                        )
                        if logs:
                            if config["alert_type"] == "player_activity":
                                logger.info(
                                    f"Processing player activity for {config['name']}"
                                )
                                self.process_player_activity_alert(config, logs)

                # Update last check time and save state
                self.last_check_time = current_time
                self.save_state()

                # Wait for next check
                time.sleep(self.check_interval)

            except KeyboardInterrupt:
                logger.info("Minecraft Alert Monitor stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in Minecraft Alert Monitor: {e}")
                time.sleep(self.check_interval)

    def process_server_health_check(self, config: Dict[str, Any]):
        """Process server health checks for Minecraft."""
        host = config.get("host", "localhost")
        port = config.get("port", 19132)

        # Check server health
        is_healthy = self.check_server_health(host, port)
        current_state = "online" if is_healthy else "offline"
        state_key = config.get("state_key", config["name"])

        # Check if state changed
        previous_state = self.server_states.get(state_key, "unknown")
        if previous_state == current_state:
            logger.info(f"Minecraft server health unchanged: {current_state}")
            return

        # State changed - send alert
        logger.info(
            f"Minecraft server health changed: {previous_state} -> {current_state}"
        )

        # Send alert
        self.send_server_health_alert(config, current_state)

        # Update state
        self.server_states[state_key] = current_state

    def send_server_health_alert(self, config: Dict[str, Any], state: str):
        """Send server health change alert."""
        try:
            color = config.get(f"color_{state}", config.get("color", 0x00FF00))

            # Use offline-specific messages if available and state is offline
            if state == "offline" and "discord_title_offline" in config:
                discord_title = config["discord_title_offline"]
                discord_message = config["discord_message_offline"]
            else:
                discord_title = config["discord_title"]
                discord_message = config["discord_message"].format(
                    state=state,
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                )

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
            logger.info(f"Sent Minecraft server health alert: {state}")

        except Exception as e:
            logger.error(f"Error sending Minecraft server health alert: {e}")

    def save_state(self):
        """Save Minecraft monitor state to Redis."""
        try:
            # Call parent save_state first
            super().save_state()

            # Save server states
            self.redis_client.set_server_states(self.server_states)

        except Exception as e:
            logger.error(f"Error saving Minecraft state: {e}")

    def store_player_mapping(self, xuid: str, username: str, timestamp: datetime):
        """Store XUID to username mapping in Redis with timestamps."""
        try:
            # Get existing player data to preserve updated_timestamp if username hasn't changed
            player_key = f"minecraft:players:{xuid}"
            existing_data = self.redis_client.get_player_mapping(player_key)

            # Create player data with both timestamps
            player_data = {
                "username": username,
                "last_online_timestamp": timestamp.isoformat(),
            }

            # If username hasn't changed, preserve the original updated_timestamp
            if existing_data and existing_data.get("username") == username:
                player_data["updated_timestamp"] = existing_data.get(
                    "updated_timestamp", timestamp.isoformat()
                )
            else:
                # Username changed or new player - update the updated_timestamp
                player_data["updated_timestamp"] = timestamp.isoformat()

            # Store in Redis
            self.redis_client.set_player_mapping(player_key, player_data)

        except Exception as e:
            logger.error(f"Error storing player mapping for XUID {xuid}: {e}")


if __name__ == "__main__":
    monitor = MinecraftAlertMonitor()
    monitor.run()
