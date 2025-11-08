"""Base alert monitor class with Redis persistence."""

import os
import requests
import time
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging
from cryptography.fernet import Fernet
from redis_utils import AlertMonitorRedis


logger = logging.getLogger(__name__)


class BaseAlertMonitor:
    """Base class for all alert monitors with Redis persistence."""

    def __init__(
        self,
        alert_configs: List[Dict[str, Any]],
        monitor_type: str,
    ):
        """Initialize the base alert monitor with Redis.

        Args:
            alert_configs: List of alert configurations for this monitor
            monitor_type: Type of monitor ('services', 'infrastructure', 'minecraft')
        """
        self.loki_url = os.getenv("LOKI_URL", "http://loki:3100")
        self.webhook_url = os.getenv(
            "WEBHOOK_URL", "http://discord-webhook:8080/webhook"
        )
        self.check_interval = int(os.getenv("CHECK_INTERVAL", "30"))  # seconds
        self.monitor_type = monitor_type

        # Initialize Redis client
        self.redis_client = AlertMonitorRedis(monitor_type)

        # Load previous state from Redis
        self.load_state()

        # Alert configurations
        self.alert_configs = alert_configs

        # Set alert monitor secret for health checks
        self.alert_monitor_secret = os.getenv(
            "ALERT_MONITOR_SECRET", "default-secret-change-me"
        )

    def load_state(self):
        """Load previous state from Redis."""
        try:
            # Load last check time
            self.last_check_time = self.redis_client.get_last_check_time()
            if not self.last_check_time:
                self.last_check_time = datetime(1970, 1, 1)
                logger.info(f"No previous state found for {self.monitor_type} monitor")

            # Server states will be loaded by individual monitors that need them

            # Load IP data (unified structure)
            all_ips = self.redis_client.get_all_ips()
            self.known_ips = {}
            self.suspicious_ips = set()
            self.ip_alert_cooldown = {}

            for ip_address, ip_data in all_ips.items():
                # Convert back to legacy format for compatibility
                self.known_ips[ip_address] = {
                    "last_seen": ip_data["last_seen"],
                    "country": ip_data["country"],
                }

                if ip_data.get("is_suspicious", False):
                    self.suspicious_ips.add(ip_address)

                # Convert cooldowns back to legacy format
                if "cooldowns" in ip_data:
                    for alert_type, cooldown_time in ip_data["cooldowns"].items():
                        key = f"{ip_address}|{alert_type}"
                        self.ip_alert_cooldown[key] = cooldown_time

            # IP location cache removed - now using unified IP data structure

            logger.info(f"Loaded state from Redis for {self.monitor_type} monitor")

        except Exception as e:
            logger.error(f"Error loading state from Redis: {e}")
            # Initialize with defaults
            self.last_check_time = datetime(1970, 1, 1)
            self.known_ips = {}
            self.suspicious_ips = set()
            self.ip_alert_cooldown = {}
            # IP location cache removed - now using unified IP data structure

    def save_state(self):
        """Save current state to Redis."""
        try:
            # Save last check time
            if self.last_check_time:
                self.redis_client.set_last_check_time(self.last_check_time)

        except Exception as e:
            logger.error(f"Error saving state to Redis: {e}")

    def cleanup_old_ips(self, max_age_days: int = 30):
        """Clean up old IP data from Redis."""
        try:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(days=max_age_days)

            all_ips = self.redis_client.get_all_ips()
            cleaned_count = 0

            for ip_address, ip_data in all_ips.items():
                if ip_data["last_seen"] < cutoff_time:
                    # Remove old IP data
                    key = self.redis_client._get_key("ips", ip_address)
                    self.redis_client.redis_client.delete(key)
                    cleaned_count += 1

                    # Remove from local state
                    if ip_address in self.known_ips:
                        del self.known_ips[ip_address]
                    if ip_address in self.suspicious_ips:
                        self.suspicious_ips.remove(ip_address)

                    # Remove cooldowns
                    keys_to_remove = [
                        k
                        for k in self.ip_alert_cooldown.keys()
                        if k.startswith(f"{ip_address}|")
                    ]
                    for key in keys_to_remove:
                        del self.ip_alert_cooldown[key]

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} old IP records from Redis")

        except Exception as e:
            logger.error(f"Error cleaning up old IPs: {e}")

    # get_ip_location method removed - now handled by individual alert monitors
    # using the unified IP data structure in Redis

    def validate_health_check_token(self, token: str) -> bool:
        """Validate a health check token."""
        try:
            if not hasattr(self, "alert_monitor_secret"):
                logger.error("alert_monitor_secret not set for this monitor")
                return False

            # Decode the token
            decoded_token = base64.urlsafe_b64decode(token.encode())

            # Create decryption key from secret
            secret = self.alert_monitor_secret
            key = base64.urlsafe_b64encode(secret.encode()[:32].ljust(32, b"0"))
            f = Fernet(key)

            # Decrypt the token
            decrypted_timestamp = f.decrypt(decoded_token)
            timestamp = int(decrypted_timestamp.decode())

            # Check if token is recent (within 5 minutes)
            current_time = int(time.time())
            if current_time - timestamp > 300:  # 5 minutes
                logger.warning("Health check token is too old")
                return False

            return True

        except Exception as e:
            logger.warning(f"Health check token validation failed: {e}")
            return False

    def generate_health_check_token(self) -> str:
        """Generate a secure health check token with encrypted timestamp."""
        try:
            if not hasattr(self, "alert_monitor_secret"):
                logger.error("alert_monitor_secret not set for this monitor")
                return "fallback-token"

            # Create a timestamp
            timestamp = int(time.time())

            # Get secret from environment
            secret = self.alert_monitor_secret

            # Create encryption key from secret (pad to 32 bytes)
            key = base64.urlsafe_b64encode(secret.encode()[:32].ljust(32, b"0"))
            f = Fernet(key)

            # Encrypt the timestamp
            encrypted_timestamp = f.encrypt(str(timestamp).encode())
            return base64.urlsafe_b64encode(encrypted_timestamp).decode()
        except Exception as e:
            logger.warning(f"Failed to generate health check token: {e}")
            return "fallback-token"

    def check_server_health(self, host: str, port: int) -> bool:
        """Check if a server is healthy by attempting a TCP connection."""
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def query_loki(self, query: str) -> List[Dict]:
        """Query Loki for logs."""
        try:
            # Calculate time range (last 5 minutes or since last check)
            end_time = datetime.now()
            if self.last_check_time:
                start_time = self.last_check_time
            else:
                start_time = end_time - timedelta(minutes=5)

            # Convert to nanoseconds (Loki expects nanoseconds)
            start_ns = int(start_time.timestamp() * 1_000_000_000)
            end_ns = int(end_time.timestamp() * 1_000_000_000)

            # Build Loki query URL
            url = f"{self.loki_url}/loki/api/v1/query_range"
            params = {"query": query, "start": start_ns, "end": end_ns, "limit": 1000}

            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            logs = []

            if "data" in data and "result" in data["data"]:
                for stream in data["data"]["result"]:
                    if "values" in stream:
                        for value in stream["values"]:
                            logs.append(
                                {
                                    "timestamp": value[0],
                                    "message": value[1],
                                    "labels": stream.get("stream", {}),
                                }
                            )

            logger.info(f"Loki query returned {len(logs)} logs")
            return logs

        except Exception as e:
            logger.error(f"Error querying Loki: {e}")
            return []

    def send_webhook(self, payload: Dict[str, Any]):
        """Send webhook notification."""
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info("Webhook sent successfully")
            else:
                logger.warning(f"Webhook failed with status {response.status_code}")
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")

    def run(self):
        """Main monitoring loop - to be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement the run method")
