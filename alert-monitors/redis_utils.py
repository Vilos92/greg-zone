#!/usr/bin/env python3
"""
Simple Redis utilities for Alert Monitor state persistence.
KISS approach - direct key-value storage with JSON serialization.
"""

import json
import redis
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional, Set

logger = logging.getLogger(__name__)


class AlertMonitorRedis:
    """Simple Redis interface for alert monitor state."""

    def __init__(self, monitor_type: str):
        """
        Initialize Redis connection for a specific monitor type.

        Args:
            monitor_type: 'services', 'infrastructure', or 'minecraft'
        """
        self.monitor_type = monitor_type
        self.redis_client = redis.Redis(
            host="infra-redis",
            port=6379,
            password=os.getenv("INFRA_REDIS_PASSWORD", "alert-monitor-redis-2024"),
            decode_responses=True,
        )

        try:
            self.redis_client.ping()
            logger.info(f"Connected to Redis for {monitor_type} monitor")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def _get_key(self, key_type: str, *args) -> str:
        """Generate Redis key with monitor type prefix."""
        key_parts = [self.monitor_type, key_type] + list(args)
        return ":".join(key_parts)

    def get_last_check_time(self) -> Optional[datetime]:
        """Get the last check time for this monitor."""
        key = self._get_key("last_check_time")
        timestamp_str = self.redis_client.get(key)
        if timestamp_str:
            return datetime.fromisoformat(timestamp_str)
        return None

    def set_last_check_time(self, check_time: datetime):
        """Set the last check time for this monitor."""
        key = self._get_key("last_check_time")
        self.redis_client.set(key, check_time.isoformat())

    def get_server_states(self) -> Dict[str, str]:
        """Get current server states for this monitor."""
        key = self._get_key("server_states")
        states_json = self.redis_client.get(key)
        if states_json:
            return json.loads(states_json)
        return {}

    def set_server_states(self, states: Dict[str, str]):
        """Set server states for this monitor."""
        key = self._get_key("server_states")
        self.redis_client.set(key, json.dumps(states))

    def update_server_state(self, service_name: str, state: str):
        """Update a single server state."""
        states = self.get_server_states()
        states[service_name] = state
        self.set_server_states(states)

    def get_ip_data(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get unified IP data for a specific IP address."""
        key = self._get_key("ips", ip_address)
        ip_json = self.redis_client.get(key)
        if ip_json:
            data = json.loads(ip_json)
            # Convert ISO strings back to datetime objects
            if "last_seen" in data:
                data["last_seen"] = datetime.fromisoformat(data["last_seen"])
            if "cooldowns" in data:
                data["cooldowns"] = {
                    k: datetime.fromisoformat(v) for k, v in data["cooldowns"].items()
                }
            return data
        return None

    def set_ip_data(self, ip_address: str, ip_data: Dict[str, Any]):
        """Set unified IP data for a specific IP address with TTL."""
        key = self._get_key("ips", ip_address)
        # Convert datetime objects to ISO strings for JSON serialization
        serializable_data = ip_data.copy()
        if "last_seen" in serializable_data and isinstance(
            serializable_data["last_seen"], datetime
        ):
            serializable_data["last_seen"] = serializable_data["last_seen"].isoformat()
        if "cooldowns" in serializable_data:
            serializable_data["cooldowns"] = {
                k: v.isoformat() if isinstance(v, datetime) else v
                for k, v in serializable_data["cooldowns"].items()
            }
        # Set with 30-day TTL (30 * 24 * 60 * 60 = 2,592,000 seconds)
        self.redis_client.setex(key, 2592000, json.dumps(serializable_data))

    def set_player_mapping(self, player_key: str, player_data: Dict[str, Any]):
        """Set player mapping data (XUID to username) without TTL."""
        # Convert datetime objects to ISO strings for JSON serialization
        serializable_data = player_data.copy()
        if "updated_timestamp" in serializable_data and isinstance(
            serializable_data["updated_timestamp"], datetime
        ):
            serializable_data["updated_timestamp"] = serializable_data[
                "updated_timestamp"
            ].isoformat()
        if "last_online_timestamp" in serializable_data and isinstance(
            serializable_data["last_online_timestamp"], datetime
        ):
            serializable_data["last_online_timestamp"] = serializable_data[
                "last_online_timestamp"
            ].isoformat()
        # Set without TTL - player mappings persist indefinitely
        self.redis_client.set(player_key, json.dumps(serializable_data))

    def get_player_mapping(self, player_key: str) -> Optional[Dict[str, Any]]:
        """Get player mapping data (XUID to username)."""
        data = self.redis_client.get(player_key)
        if data:
            return json.loads(data)
        return None

    def get_all_ips(self) -> Dict[str, Dict[str, Any]]:
        """Get all IPs for this monitor."""
        pattern = self._get_key("ips", "*")
        keys = self.redis_client.keys(pattern)
        ips = {}
        for key in keys:
            ip_address = key.split(":")[-1]  # Extract IP from key
            ip_data = self.get_ip_data(ip_address)
            if ip_data:
                ips[ip_address] = ip_data
        return ips

    def update_ip(
        self,
        ip_address: str,
        last_seen: datetime,
        country: str = "Unknown",
        is_suspicious: bool = False,
        alert_count: int = 0,
    ):
        """Update or add IP data with unified structure."""
        existing_data = self.get_ip_data(ip_address) or {}

        ip_data = {
            "last_seen": last_seen,
            "country": country,
            "is_suspicious": is_suspicious or existing_data.get("is_suspicious", False),
            "alert_count": alert_count + existing_data.get("alert_count", 0),
            "cooldowns": existing_data.get("cooldowns", {}),
        }

        self.set_ip_data(ip_address, ip_data)

    def mark_ip_suspicious(self, ip_address: str):
        """Mark an IP as suspicious."""
        existing_data = self.get_ip_data(ip_address) or {}
        existing_data["is_suspicious"] = True
        existing_data["alert_count"] = existing_data.get("alert_count", 0) + 1
        self.set_ip_data(ip_address, existing_data)

    def set_ip_cooldown(
        self, ip_address: str, alert_type: str, cooldown_until: datetime
    ):
        """Set a cooldown for a specific IP and alert type."""
        existing_data = self.get_ip_data(ip_address) or {}
        if "cooldowns" not in existing_data:
            existing_data["cooldowns"] = {}
        existing_data["cooldowns"][alert_type] = cooldown_until
        self.set_ip_data(ip_address, existing_data)

    def get_suspicious_ips(self) -> Set[str]:
        """Get all suspicious IPs for this monitor."""
        all_ips = self.get_all_ips()
        return {ip for ip, data in all_ips.items() if data.get("is_suspicious", False)}

    def get_ip_alert_cooldowns(self) -> Dict[str, datetime]:
        """Get all IP alert cooldowns for this monitor."""
        all_ips = self.get_all_ips()
        cooldowns = {}
        for ip, data in all_ips.items():
            if "cooldowns" in data:
                for alert_type, cooldown_time in data["cooldowns"].items():
                    key = f"{ip}|{alert_type}"
                    cooldowns[key] = cooldown_time
        return cooldowns

    # Note: IP location cache removed - now using unified IP data structure
    # Each IP stores its country directly in the IP data via update_ip() method
