#!/usr/bin/env python3
"""
Copyparty Discord Notification Hook
Called by copyparty when files are uploaded
"""

import sys
import urllib.request
import urllib.parse
import json
from pathlib import Path


def send_discord_notification(file_path):
    """Send upload notification to discord-webhook service"""

    # Extract file information
    path = Path(file_path)
    filename = path.name
    file_size = path.stat().st_size if path.exists() else 0
    file_ext = path.suffix.lower()

    # Format file size
    if file_size < 1024:
        size_str = f"{file_size} B"
    elif file_size < 1024**2:
        size_str = f"{file_size / 1024:.1f} KB"
    elif file_size < 1024**3:
        size_str = f"{file_size / (1024**2):.1f} MB"
    else:
        size_str = f"{file_size / (1024**3):.1f} GB"

    # Determine file type emoji and color
    if file_ext in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"]:
        emoji = "🖼️"
        color = 0x00FF99
    elif file_ext in [".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv"]:
        emoji = "🎬"
        color = 0x0099FF
    elif file_ext in [".mp3", ".wav", ".flac", ".aac", ".ogg"]:
        emoji = "🎵"
        color = 0xFF6B6B
    elif file_ext in [".pdf", ".doc", ".docx", ".txt", ".rtf"]:
        emoji = "📄"
        color = 0x99CCFF
    elif file_ext in [".zip", ".rar", ".7z", ".tar", ".gz"]:
        emoji = "📦"
        color = 0xFFAA00
    else:
        emoji = "📁"
        color = 0x666666

    # Create Discord embed
    embed = {
        "title": f"{emoji} File Uploaded",
        "description": f"**{filename}**",
        "color": color,
        "fields": [
            {"name": "📁 File", "value": filename, "inline": True},
            {"name": "📏 Size", "value": size_str, "inline": True},
            {"name": "📂 Path", "value": f"`{file_path}`", "inline": False},
        ],
        "footer": {"text": "Copyparty Upload Monitor"},
    }

    payload = {"embeds": [embed]}

    # Send to discord-webhook service
    webhook_url = "http://discord-webhook:8080/copyparty-upload"

    try:
        # Convert payload to JSON bytes
        data = json.dumps(payload).encode("utf-8")

        # Create request
        req = urllib.request.Request(
            webhook_url, data=data, headers={"Content-Type": "application/json"}
        )

        # Send request
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200 or response.status == 204:
                print(f"Discord notification sent for: {filename}")
            else:
                print(
                    f"Discord webhook returned status {response.status}",
                    file=sys.stderr,
                )

    except Exception as e:
        print(f"Failed to send Discord notification: {e}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: copyparty-discord-hook.py <arg1> <json_data>", file=sys.stderr)
        sys.exit(1)

    # Parse JSON data from argv[2]
    try:
        inf = json.loads(sys.argv[2])
        file_path = inf.get("ap", "")  # absolute path
        send_discord_notification(file_path)
    except json.JSONDecodeError:
        print("Failed to parse JSON data", file=sys.stderr)
        sys.exit(1)
