#!/usr/bin/env python3
"""
Docker Stats Exporter for Prometheus
Works with Docker Desktop on macOS by using Docker's built-in stats API
"""

import time
import docker
from prometheus_client import start_http_server, Gauge
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prometheus metrics
container_cpu_usage = Gauge(
    "container_cpu_usage_percent", "Container CPU usage percentage", ["name"]
)
container_memory_usage = Gauge(
    "container_memory_usage_bytes", "Container memory usage in bytes", ["name"]
)
container_memory_limit = Gauge(
    "container_memory_limit_bytes", "Container memory limit in bytes", ["name"]
)
container_network_rx = Gauge(
    "container_network_receive_bytes", "Container network receive bytes", ["name"]
)
container_network_tx = Gauge(
    "container_network_transmit_bytes",
    "Container network transmit bytes",
    ["name"],
)
container_disk_read = Gauge(
    "container_fs_reads_bytes_total", "Container disk read bytes total", ["name"]
)
container_disk_write = Gauge(
    "container_fs_writes_bytes_total",
    "Container disk write bytes total",
    ["name"],
)


def parse_cpu_percent(cpu_str):
    """Parse CPU percentage string like '0.24%' to float"""
    try:
        return float(cpu_str.replace("%", ""))
    except Exception:
        return 0.0


def parse_memory(mem_str):
    """Parse memory string like '18.34MiB / 7.653GiB' to bytes"""
    try:
        usage_part = mem_str.split(" / ")[0]
        if "MiB" in usage_part:
            return float(usage_part.replace("MiB", "")) * 1024 * 1024
        elif "GiB" in usage_part:
            return float(usage_part.replace("GiB", "")) * 1024 * 1024 * 1024
        elif "KiB" in usage_part:
            return float(usage_part.replace("KiB", "")) * 1024
        else:
            return float(usage_part)
    except Exception:
        return 0.0


def get_container_stats():
    """Get container stats from Docker API"""
    try:
        client = docker.from_env()
        containers = client.containers.list()

        # Track which containers we've seen to clean up old metrics
        current_containers = set()

        for container in containers:
            # Get container info
            name = container.name
            container_id = container.id
            current_containers.add(name)

            try:
                stats = container.stats(stream=False)

                # Parse CPU usage
                cpu_delta = (
                    stats["cpu_stats"]["cpu_usage"]["total_usage"]
                    - stats["precpu_stats"]["cpu_usage"]["total_usage"]
                )
                system_delta = (
                    stats["cpu_stats"]["system_cpu_usage"]
                    - stats["precpu_stats"]["system_cpu_usage"]
                )

                # Handle different CPU stats structures
                if "percpu_usage" in stats["cpu_stats"]["cpu_usage"]:
                    cpu_count = len(stats["cpu_stats"]["cpu_usage"]["percpu_usage"])
                else:
                    cpu_count = 1

                if system_delta > 0:
                    cpu_percent = (cpu_delta / system_delta) * cpu_count * 100.0
                else:
                    cpu_percent = 0.0

                # Parse memory usage
                memory_usage = stats["memory_stats"]["usage"]
                memory_limit = stats["memory_stats"]["limit"]

                # Parse network stats
                network_stats = stats.get("networks", {})
                if network_stats:
                    rx_bytes = sum(net["rx_bytes"] for net in network_stats.values())
                    tx_bytes = sum(net["tx_bytes"] for net in network_stats.values())
                else:
                    rx_bytes = 0
                    tx_bytes = 0

                # Parse disk I/O stats
                blkio_stats = stats.get("blkio_stats", {})
                read_bytes = 0
                write_bytes = 0

                if blkio_stats and "io_service_bytes_recursive" in blkio_stats:
                    io_entries = blkio_stats["io_service_bytes_recursive"]
                    if io_entries:  # Check if not None
                        for entry in io_entries:
                            if entry.get("op") == "read":
                                read_bytes += entry.get("value", 0)
                            elif entry.get("op") == "write":
                                write_bytes += entry.get("value", 0)

                # Update Prometheus metrics
                container_cpu_usage.labels(name=name).set(cpu_percent)
                container_memory_usage.labels(name=name).set(memory_usage)
                container_memory_limit.labels(name=name).set(memory_limit)
                container_network_rx.labels(name=name).set(rx_bytes)
                container_network_tx.labels(name=name).set(tx_bytes)
                container_disk_read.labels(name=name).set(read_bytes)
                container_disk_write.labels(name=name).set(write_bytes)

                logger.info(f"Updated metrics for {name} ({container_id})")

            except Exception as e:
                logger.error(f"Error getting stats for container {container.name}: {e}")

        # Clean up metrics for containers that no longer exist
        cleanup_old_metrics(current_containers)

    except Exception as e:
        logger.error(f"Error connecting to Docker: {e}")


def cleanup_old_metrics(current_containers):
    """Remove metrics for containers that no longer exist"""
    try:
        # Get all current metric labels
        all_metrics = [
            container_cpu_usage,
            container_memory_usage,
            container_memory_limit,
            container_network_rx,
            container_network_tx,
            container_disk_read,
            container_disk_write,
        ]

        for metric in all_metrics:
            # Get all current labels for this metric
            for sample in metric.collect()[0].samples:
                if sample.name == metric._name and "name" in sample.labels:
                    container_name = sample.labels["name"]
                    if container_name not in current_containers:
                        # Remove the metric for this container
                        metric.remove(container_name)
                        logger.info(
                            f"Cleaned up metrics for removed container: {container_name}"
                        )
    except Exception as e:
        logger.error(f"Error cleaning up old metrics: {e}")


def main():
    """Main function"""
    logger.info("Starting Docker Stats Exporter on port 8081")

    # Start Prometheus metrics server
    start_http_server(8081)

    # Main loop
    while True:
        try:
            get_container_stats()
            time.sleep(10)  # Update every 10 seconds
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            time.sleep(10)


if __name__ == "__main__":
    main()
