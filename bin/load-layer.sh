#!/usr/bin/env bash
# Copy a generated Navigator layer into ./layers/ so the running viewer can serve
# it. Usage:
#   bin/load-layer.sh /path/to/layer.json            # -> layers/layer.json (default)
#   bin/load-layer.sh /path/to/layer.json prod.json  # -> layers/prod.json
set -euo pipefail

src="${1:?usage: load-layer.sh <layer.json> [dest-name]}"
dest="${2:-layer.json}"
here="$(cd "$(dirname "$0")/.." && pwd)"

cp "$src" "$here/layers/$dest"
echo "Loaded $src -> layers/$dest"
echo "  Custom viewer : http://localhost:8080  (click 'Load layers/$dest' or it auto-loads layer.json)"
echo "  Official Nav  : http://localhost:4200/#layerURL=http://localhost:8080/layers/$dest"
