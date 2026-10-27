#!/usr/bin/env bash
# Download the public peer list for the platform to feed into
# Endpoint::import_peer_list. Default source is the public-peers JSON.
#   PEERS_URL=<url> scripts/fetch-peers.sh [output-file]
set -euo pipefail
url="${PEERS_URL:-https://publicpeers.neilalexander.dev/publicnodes.json}"
out="${1:-peers.json}"
curl -fsSL --max-time 30 "$url" -o "$out"
echo "saved $(wc -c < "$out") bytes from $url to $out"
