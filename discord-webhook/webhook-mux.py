#!/usr/bin/env python3
"""
Webhook Multiplexer Service
Receives alerts and routes them to appropriate Discord webhooks based on service type
"""

import os
import json
import requests
import logging
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Discord webhook URLs from environment
DISCORD_WEBHOOKS = {
    "minecraft": os.getenv("DISCORD_JORDANIA_WEBHOOK_URL"),
    "copyparty": os.getenv("DISCORD_COPYPARTY_WEBHOOK_URL"),
    "plex": os.getenv("DISCORD_PLEX_WEBHOOK_URL"),
    "nginx": os.getenv("DISCORD_NGINX_WEBHOOK_URL"),
    "infra": os.getenv("DISCORD_INFRA_WEBHOOK_URL"),
}


def send_discord_message(service, title, message, color=0x00FF00):
    """Send a formatted message to the appropriate Discord webhook"""
    # Route nginx security alerts to nginx webhook
    if service.startswith("nginx") or service == "nginx":
        webhook_url = DISCORD_WEBHOOKS.get("nginx")
        logger.info(f"Routing nginx alert to nginx webhook: {service}")
    else:
        webhook_url = DISCORD_WEBHOOKS.get(service)

    if not webhook_url:
        logger.error(f"No Discord webhook URL configured for service: {service}")
        return False

    embed = {
        "title": title,
        "description": message,
        "color": color,
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {"text": f"{service.title()} Alert Monitor"},
    }

    payload = {"embeds": [embed]}

    try:
        logger.info(
            f"Sending Discord payload to {service}: {json.dumps(payload, indent=2)}"
        )
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info(f"Discord message sent to {service}: {title}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Discord message to {service}: {e}")
        return False


@app.route("/webhook/container-health", methods=["POST"])
def container_health_webhook():
    """Handle container health alerts from Prometheus/Alertmanager"""
    try:
        data = request.get_json()
        logger.info(f"Received container health webhook: {json.dumps(data, indent=2)}")

        # Extract alert information from Alertmanager format
        alerts = data.get("alerts", [])

        for alert in alerts:
            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})
            status = alert.get("status", "unknown")

            # Debug: log the full alert structure
            logger.info(f"Alert labels: {labels}")
            logger.info(f"Alert annotations: {annotations}")

            # Extract information
            alertname = labels.get("alertname", "Unknown Alert")
            container_name = (
                labels.get("container_name")
                or labels.get("name")
                or "Unknown Container"
            )
            image = labels.get("image", "Unknown Image")
            severity = labels.get("severity", "unknown")

            # Check if this is a resolved alert
            is_resolved = status == "resolved"

            # Create title and description based on status
            if is_resolved:
                title = f"✅ {alertname.replace('_', ' ').replace('ContainerDown', 'Container Down').title()} - Resolved"
                summary = f"Container {container_name} is back up"
                description = (
                    f"Container {container_name} has recovered and is running normally."
                )
                color = 0x00FF00  # Green for resolved
            else:
                title = f"🚨 {alertname.replace('_', ' ').replace('ContainerDown', 'Container Down').title()}"
                summary = annotations.get("summary", alertname)
                description = annotations.get("description", "No description available")
                # Set color based on severity
                if severity == "critical":
                    color = 0xFF0000  # Red
                elif severity == "warning":
                    color = 0xFFAA00  # Orange
                else:
                    color = 0x00FF00  # Green

            # Create detailed message
            message = f"**📦 Container:** `{container_name}`\n"
            if image != "Unknown Image":
                message += f"**🏷️ Image:** `{image}`\n"
            message += f"**🔍 Summary:** {summary}\n"
            message += f"**📝 Description:** {description}\n"

            # Send to infrastructure webhook for container health alerts
            success = send_discord_message("infra", title, message, color)
            if success:
                logger.info(
                    f"Sent container health alert: {alertname} for {container_name}"
                )
            else:
                logger.error(f"Failed to send container health alert: {alertname}")

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.error(f"Error processing container health webhook: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/webhook", methods=["POST"])
def webhook():
    """Handle incoming webhook from alert-monitor"""
    try:
        data = request.get_json()
        logger.info(f"Received webhook: {json.dumps(data, indent=2)}")

        # Extract alert information
        alerts = data.get("alerts", [])
        payload_color = data.get("color")  # Get color from payload if available

        for alert in alerts:
            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})
            status = alert.get("status", "unknown")

            # Only process firing alerts
            if status != "firing":
                continue

            # Extract information
            service = labels.get("service", "unknown")
            alert_type = labels.get("alert_type", "unknown")
            event_type = labels.get("event_type", "unknown")
            current_state = labels.get("current_state", "unknown")
            username = labels.get("username", "Unknown User")

            # Get Discord message from annotations
            discord_title = annotations.get("discord_title", f"{service.title()} Alert")
            base_message = annotations.get(
                "discord_message", f"A {service} event occurred"
            )

            # Handle different alert types based on service
            if service == "minecraft":
                if alert_type == "server_health_change":
                    # Server health alerts - use state-based colors
                    discord_message = base_message
                    color = 0x00FF00 if current_state == "online" else 0xFF0000
                elif alert_type == "player_activity":
                    # Player activity alerts - use event-based colors (XUID already in message)
                    discord_message = base_message
                    color = 0x0099FF if event_type == "joined" else 0xFFAA00
                else:
                    # Default for other minecraft alert types
                    discord_message = base_message
                    color = 0x0099FF

            elif service == "copyparty":
                if alert_type == "user_activity":
                    # User activity alerts
                    discord_message = f"**{username}** is using copyparty"
                    color = 0x00FF99
                else:
                    # Default for other copyparty alert types
                    discord_message = base_message
                    color = 0x0099FF
            else:
                # Default handling for unknown services
                discord_message = base_message
                color = 0x0099FF

            # Use color from payload if available (overrides the above logic)
            if payload_color is not None:
                color = payload_color

            # Send to appropriate Discord webhook
            success = send_discord_message(
                service, discord_title, discord_message, color
            )

            if success:
                return jsonify({"status": "success", "message": "Alert processed"})
            else:
                return jsonify(
                    {"status": "error", "message": "Failed to send Discord message"}
                ), 500

    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "success", "message": "No alerts to process"})


def parse_plex_metadata(metadata):
    """Parse Plex metadata and return formatted information"""
    if not metadata:
        return "Unknown Media", "Unknown"

    media_type = metadata.get("type", "unknown")
    title = metadata.get("title", "Unknown Title")

    # Handle different media types
    if media_type == "movie":
        year = metadata.get("year", "")
        return f"🎬 {title}" + (f" ({year})" if year else ""), "Movie"
    elif media_type == "episode":
        show_title = metadata.get("grandparentTitle", "Unknown Show")
        season = metadata.get("parentIndex", "")
        episode = metadata.get("index", "")
        return f"📺 {show_title} - S{season:02d}E{episode:02d}: {title}", "TV Show"
    elif media_type == "track":
        artist = metadata.get("grandparentTitle", "Unknown Artist")
        album = metadata.get("parentTitle", "Unknown Album")
        return f"🎵 {artist} - {album} - {title}", "Music"
    elif media_type == "artist":
        return f"🎤 {title}", "Artist"
    elif media_type == "album":
        artist = metadata.get("grandparentTitle", "Unknown Artist")
        return f"💿 {artist} - {title}", "Album"
    else:
        return f"📄 {title}", media_type.title()


def get_plex_event_info(event_type):
    """Get event information and color for Plex events"""
    event_info = {
        "media.play": {"emoji": "▶️", "action": "Started playing", "color": 0x00FF00},
        "media.pause": {"emoji": "⏸️", "action": "Paused", "color": 0xFFAA00},
        "media.resume": {"emoji": "▶️", "action": "Resumed playing", "color": 0x00FF00},
        "media.stop": {"emoji": "⏹️", "action": "Stopped playing", "color": 0xFF0000},
        "media.scrobble": {
            "emoji": "✅",
            "action": "Finished watching",
            "color": 0x00FF88,
        },
        "media.rate": {"emoji": "⭐", "action": "Rated", "color": 0xFFDD00},
        "library.new": {
            "emoji": "🆕",
            "action": "New content added",
            "color": 0x0099FF,
        },
        "library.on.deck": {
            "emoji": "📋",
            "action": "Added to On Deck",
            "color": 0x0099FF,
        },
        "playback.started": {
            "emoji": "👥",
            "action": "Shared user started playback",
            "color": 0x00FF99,
        },
        "device.new": {
            "emoji": "📱",
            "action": "New device connected",
            "color": 0x99CCFF,
        },
        "admin.database.backup": {
            "emoji": "💾",
            "action": "Database backup completed",
            "color": 0x00FF00,
        },
        "admin.database.corrupted": {
            "emoji": "⚠️",
            "action": "Database corruption detected",
            "color": 0xFF0000,
        },
    }
    return event_info.get(
        event_type, {"emoji": "📡", "action": "Plex Event", "color": 0x666666}
    )


@app.route("/plex-webhook", methods=["POST"])
def plex_webhook():
    """Handle incoming webhook from Plex Media Server"""
    try:
        # Debug logging
        logger.info(f"Content-Type: {request.content_type}")
        logger.info(f"Form data: {dict(request.form)}")
        logger.info(f"Raw data: {request.get_data()}")

        # Plex sends data as multipart/form-data with JSON in 'payload' parameter
        if (
            "multipart/form-data" in request.content_type
            or "application/x-www-form-urlencoded" in request.content_type
        ):
            payload_data = request.form.get("payload")
            if payload_data:
                data = json.loads(payload_data)
            else:
                logger.error("No payload parameter in form data")
                return jsonify(
                    {"status": "error", "message": "No payload parameter"}
                ), 400
        else:
            # Fallback to direct JSON (for testing)
            data = request.get_json()

        logger.info(f"Received Plex webhook: {json.dumps(data, indent=2)}")

        if not data:
            logger.error("No data received in Plex webhook")
            return jsonify({"status": "error", "message": "No data received"}), 400

        # Extract event information
        event_type = data.get("event", "unknown")
        account = data.get("Account", {})
        server = data.get("Server", {})
        player = data.get("Player", {})
        metadata = data.get("Metadata", {})

        # Get event details
        event_info = get_plex_event_info(event_type)

        # Parse metadata
        media_title, media_type = parse_plex_metadata(metadata)

        # Build Discord message
        username = account.get("title", "Unknown User")
        server_name = server.get("title", "Unknown Server")
        player_name = player.get("title", "Unknown Player")
        is_local = player.get("local", False)

        # Create embed
        embed = {
            "title": f"{event_info['emoji']} {event_info['action']}",
            "description": f"**{media_title}**",
            "color": event_info["color"],
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [
                {"name": "👤 User", "value": username, "inline": True},
                {"name": "🖥️ Server", "value": server_name, "inline": True},
                {
                    "name": "📱 Player",
                    "value": f"{player_name} {'(Local)' if is_local else '(Remote)'}",
                    "inline": True,
                },
                {"name": "📂 Type", "value": media_type, "inline": True},
                {"name": "🎯 Event", "value": event_type, "inline": True},
            ],
            "footer": {"text": "Plex Media Server"},
        }

        # Add thumbnail if available (for media events)
        if metadata.get("thumb") and event_type in [
            "media.play",
            "media.rate",
            "library.new",
            "library.on.deck",
            "playback.started",
        ]:
            # Plex thumbnails are relative URLs, need to construct full URL
            server_url = f"http://{server.get('uuid', 'localhost')}"
            thumb_url = f"{server_url}{metadata.get('thumb')}"
            embed["thumbnail"] = {"url": thumb_url}

        # Add additional fields for specific events
        if event_type == "media.rate":
            rating = metadata.get("rating", "Unknown")
            embed["fields"].append(
                {"name": "⭐ Rating", "value": f"{rating}/10", "inline": True}
            )

        if event_type == "library.new":
            library_section = metadata.get("librarySectionType", "Unknown")
            embed["fields"].append(
                {
                    "name": "📚 Library Section",
                    "value": library_section.title(),
                    "inline": True,
                }
            )

        # Send to Discord
        success = send_discord_message(
            "plex",
            f"{event_info['emoji']} Plex Event",
            f"{event_info['action']}: {media_title}",
            event_info["color"],
        )

        if success:
            return jsonify({"status": "success", "message": "Plex webhook processed"})
        else:
            return jsonify(
                {"status": "error", "message": "Failed to send Discord message"}
            ), 500

    except Exception as e:
        logger.error(f"Error processing Plex webhook: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/copyparty-upload", methods=["POST"])
def copyparty_upload():
    """Handle copyparty file upload notifications"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400

        # Get the copyparty webhook URL
        webhook_url = os.getenv("DISCORD_COPYPARTY_WEBHOOK_URL")
        if not webhook_url:
            logger.error("DISCORD_COPYPARTY_WEBHOOK_URL not configured")
            return jsonify(
                {"status": "error", "message": "Discord webhook not configured"}
            ), 500

        # Forward the embed data to Discord
        response = requests.post(webhook_url, json=data, timeout=10)

        if response.status_code in [200, 204]:
            logger.info("Copyparty upload notification sent successfully")
            return jsonify({"status": "success"}), 200
        else:
            logger.error(
                f"Discord webhook returned status {response.status_code}: {response.text}"
            )
            return jsonify(
                {
                    "status": "error",
                    "message": f"Discord webhook failed: {response.status_code}",
                }
            ), 500

    except Exception as e:
        logger.error(f"Error processing copyparty upload: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "service": "webhook-mux",
            "configured_services": list(DISCORD_WEBHOOKS.keys()),
            "endpoints": ["/webhook", "/plex-webhook", "/copyparty-upload", "/health"],
        }
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
