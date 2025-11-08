"""Shared utility functions for alert monitors."""

from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def format_nginx_timestamp(time_str: str) -> str:
    """Convert nginx timestamp to clean UTC format."""
    try:
        # Parse nginx format: 16/Oct/2025:00:00:44 +0000
        dt = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
        # Format as clean UTC: 2025-10-16 00:00:44 UTC
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        # Fallback to original if parsing fails
        return time_str
