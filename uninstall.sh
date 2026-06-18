#!/usr/bin/env bash
#
# Tear down the on-prem viewer for a fresh start: stop and remove this project's
# containers, the locally-built Navigator image, its network and volumes. Only
# attack-navigator resources are touched — unrelated containers are left alone.
#
# Usage:
#   ./uninstall.sh            # remove containers + image + network + volumes
#   ./uninstall.sh --layers   # also delete generated layers (keeps sample-layer.json)
#
# Bring it back up afterwards with:  docker compose up -d viewer
set -euo pipefail
cd "$(dirname "$0")"

echo "==> docker compose down (containers, network, volumes, local image)"
docker compose down --rmi local --volumes --remove-orphans 2>/dev/null || true

echo "==> Removing any leftover attack-navigator containers"
# Match by compose project name or the images this project uses, so we never
# remove unrelated containers (e.g. a Tenable SC lab box).
ids="$(docker ps -aq \
  --filter "name=attack-navigator" \
  --filter "ancestor=attack-navigator:local" \
  --filter "ancestor=mitre/attack-navigator" 2>/dev/null | sort -u)"
if [ -n "${ids}" ]; then
  docker rm -f ${ids} 2>/dev/null || true
fi

echo "==> Removing the locally-built Navigator image"
docker image rm attack-navigator:local 2>/dev/null || true

if [ "${1:-}" = "--layers" ]; then
  echo "==> Clearing generated layers (keeping sample-layer.json)"
  find layers -type f -name '*.json' ! -name 'sample-layer.json' -delete 2>/dev/null || true
fi

echo "Done. Fresh start: docker compose up -d viewer  (then open http://localhost:8080)"
