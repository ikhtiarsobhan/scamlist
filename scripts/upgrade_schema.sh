#!/usr/bin/env bash
set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL is not set. Example:" >&2
  echo "  export DATABASE_URL=postgresql://USER:PASSWORD@HOST:PORT/DB?sslmode=require" >&2
  exit 1
fi

psql "$DATABASE_URL" -f "$(dirname "$0")/upgrade_schema.sql"
