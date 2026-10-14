#!/usr/bin/env bash
# Start the native binary (built with `go build -o /tmp/openbao .`) against the
# local harness Postgres with the static seal key from wasm/worker/.dev.vars.
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN="${BAO_BINARY:-/tmp/openbao}"
export BAO_STATIC_SEAL_CURRENT_KEY="$(sed -n 's/^BAO_STATIC_SEAL_CURRENT_KEY=//p' wasm/worker/.dev.vars)"
exec "$BIN" server -config wasm/harness/native-server.hcl "$@"
