#!/usr/bin/env bash
set -euo pipefail

out="${1:-schemas/config/v1.json}"

mkdir -p "$(dirname "$out")"

cargo run -p aegis-config --example gen-schema > "$out"

echo "schema written to $out"
