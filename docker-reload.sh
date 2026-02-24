#!/bin/sh

echo "🚀 Killing all Docker processes..."
pkill -9 -f Docker

sleep 2

echo "♻️Reviving Docker Desktop..."
open -a Docker

echo "⏳Waiting for Docker daemon to be ready..."
until docker info >/dev/null 2>&1; do
  echo "...still booting..."
  sleep 2
done

docker compose pull && docker compose up -d

echo "🧹 Cleaning up old image layers..."
docker image prune -f
