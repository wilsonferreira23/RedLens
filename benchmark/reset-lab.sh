#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${LAB_DIR}/lab-compose.yml"

function wait_healthy() {
    local name="$1"
    echo "Waiting for ${name} to become healthy..."
    for i in {1..60}; do
        status=$(docker inspect --format='{{.State.Health.Status}}' "${name}" 2>/dev/null || echo "unhealthy")
        if [ "${status}" = "healthy" ]; then
            echo "${name} is healthy."
            return 0
        fi
        sleep 2
    done
    echo "Timeout waiting for ${name}."
    docker compose -f "${COMPOSE_FILE}" logs --tail 50 "${name}"
    return 1
}

echo "Resetting RedLens benchmark lab..."

docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans || true
docker compose -f "${COMPOSE_FILE}" pull
docker compose -f "${COMPOSE_FILE}" up -d

wait_healthy "redlens-juice-shop"
wait_healthy "redlens-vampi"

echo ""
echo "RedLens lab is ready:"
echo "  Juice Shop  -> http://localhost:13000"
echo "  VAmPI       -> http://localhost:15000"
