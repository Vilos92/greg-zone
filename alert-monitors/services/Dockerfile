FROM python:3.11-alpine

WORKDIR /app

# Install system dependencies (cached layer)
RUN apk add --no-cache curl jq

# Copy requirements first for better layer caching
COPY services/requirements.txt .

# Install Python dependencies (cached layer if requirements.txt unchanged)
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared utilities (cached layer if unchanged)
COPY shared/ ./shared/

# Copy application code (changes most frequently)
COPY services/services_alert_monitor.py .
COPY redis_utils.py .

# Create non-root user (cached layer)
RUN adduser -D -s /bin/sh alertmonitor

# Switch to non-root user
USER alertmonitor

# Run the alert monitor
CMD ["python3", "services_alert_monitor.py"]
