#!/usr/bin/env bash
#
# Launcher for the Facet shopping MCP server on Meta Muse Code.
#
# Muse spawns this as the command for the "facet-shopping" entry in
# ~/.config/muse/settings.json. It runs the same stdio MCP server the README
# documents, from wherever this repository is checked out.
#
# Secret-free by construction: the wallet key is read from the environment
# (FACET_WALLET_KEY), used only inside the Deno process, and never lives in this
# file, in settings.json, or on a command line. Do not add a key here.
#
# Environment the caller (Muse) must pass through:
#   FACET_WALLET_KEY   your wallet private key (0x + 64 hex); signs locally
#   FACET_KYA          optional; a wallet-bound KYA is self-issued if absent
#
set -euo pipefail

# Resolve the repository root from this script's own location, so the launcher
# works no matter where the repo is cloned and no matter Muse's working dir.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v deno >/dev/null 2>&1; then
  echo "facet-shopping: deno is not on PATH. Install it from https://deno.com" >&2
  exit 127
fi

exec deno run \
  --allow-env \
  --allow-read \
  --allow-run \
  --allow-net \
  --allow-write="$HOME/.cache,$HOME/.facet" \
  "$repo_root/scripts/mcp-server.ts"
