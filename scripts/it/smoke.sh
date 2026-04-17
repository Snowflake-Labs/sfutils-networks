#!/usr/bin/env bash
# Minimal integration smoke for sfutils-networks.
# Runs dry-runs only — no Snowflake DDL, no network rule creation.
# Requires: snow CLI on PATH, uv, repo synced.
#
# Loads .env from repo root when present.
# DB resolution: SF_UTILS_DB > SNOW_UTILS_DB > "SF_UTILS"

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

_DRY_DB="${SF_UTILS_DB:-${SNOW_UTILS_DB:-SF_UTILS}}"

echo "== snow connection test =="
snow connection test --format json | head -c 800
echo
echo

echo "== sfutils-networks rule create --dry-run (SQL generation, no DDL) =="
uv run sfutils-networks rule create \
  --name SMOKE_RULE \
  --db "$_DRY_DB" \
  --dry-run \
  --no-local \
  --values "1.2.3.4/32"

echo
echo "== sfutils-networks rule create --dry-run --allow-gh (fetches GitHub IPs) =="
uv run sfutils-networks rule create \
  --name CI_RULE \
  --db "$_DRY_DB" \
  --dry-run \
  --no-local \
  --allow-gh

echo
echo "== sfutils-networks policy create --dry-run =="
uv run sfutils-networks policy create \
  --name SMOKE_POLICY \
  --rules "${_DRY_DB}.NETWORKS.SMOKE_RULE" \
  --dry-run

echo
echo "== sfutils-networks policy alter --dry-run =="
uv run sfutils-networks policy alter \
  --name SMOKE_POLICY \
  --rules "${_DRY_DB}.NETWORKS.EXTRA_RULE" \
  --dry-run

echo
echo "== smoke OK =="
