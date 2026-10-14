#!/usr/bin/env bash
# Drop OpenBao's tables in the local harness database so the next run starts from
# an uninitialised store. PG_URL defaults to the local harness instance.
set -euo pipefail
PG_URL="${PG_URL:-postgres://bao:bao@127.0.0.1:5432/bao?sslmode=disable}"
psql "$PG_URL" -q -c "DROP TABLE IF EXISTS openbao_kv_store; DROP TABLE IF EXISTS openbao_ha_locks;"
echo "reset $PG_URL"
