FROM python:3.11-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache curl jq

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY webhook-mux.py .

# Create non-root user
RUN adduser -D -s /bin/sh webhookmux

# Switch to non-root user
USER webhookmux

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["python", "webhook-mux.py"]