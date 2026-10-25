#!/usr/bin/env bash
# update-data.sh — refresh vendored Crawler-Detect pattern data.
#
# Fetches the latest raw lists from JayBizzle/Crawler-Detect (MIT) and
# writes them into data/. Run tests afterwards:
#
#   scripts/update-data.sh && go test ./...
set -euo pipefail

BASE="https://raw.githubusercontent.com/JayBizzle/Crawler-Detect/master/raw"
DIR="$(cd "$(dirname "$0")/../data" && pwd)"

for name in Crawlers Exclusions Headers; do
  curl -fsSL "$BASE/$name.json" -o "$DIR/$(echo "$name" | tr 'A-Z' 'a-z').json"
  echo "updated $name"
done
