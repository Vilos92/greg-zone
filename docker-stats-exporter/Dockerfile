FROM python:3.11-alpine

# Install dependencies
RUN pip install docker prometheus_client

# Copy the exporter script
COPY docker-stats-exporter.py /app/docker-stats-exporter.py

# Make it executable
RUN chmod +x /app/docker-stats-exporter.py

# Expose port
EXPOSE 8081

# Run the exporter
CMD ["python", "/app/docker-stats-exporter.py"]
