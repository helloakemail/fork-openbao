#!/usr/bin/env bash
# Run the Worker bundle under workerd (wrangler dev) against the local harness
# Postgres. Logs go to /tmp/wrangler-dev.log; the API is on http://127.0.0.1:8787.
#   wasm/harness/workerd.sh start|stop|status
set -euo pipefail
cd "$(dirname "$0")/../worker"
PIDF=/tmp/wrangler-dev.pid
case "${1:-start}" in
  start)
    [ -f build/app.wasm ] || { echo "build first: wasm/harness/build.sh" >&2; exit 1; }
    if [ -f $PIDF ] && kill -0 "$(cat $PIDF)" 2>/dev/null; then echo "already running"; exit 0; fi
    nohup npx wrangler dev --port 8787 --ip 127.0.0.1 --log-level info > /tmp/wrangler-dev.log 2>&1 &
    echo $! > $PIDF
    for i in $(seq 1 120); do curl -sf -o /dev/null http://127.0.0.1:8787/_worker/mem 2>/dev/null && { echo "workerd up (pid $(cat $PIDF))"; exit 0; }; sleep 1; done
    echo "workerd did not come up; see /tmp/wrangler-dev.log" >&2; tail -30 /tmp/wrangler-dev.log; exit 1;;
  stop) [ -f $PIDF ] && { pkill -P "$(cat $PIDF)" 2>/dev/null || true; kill "$(cat $PIDF)" 2>/dev/null || true; rm -f $PIDF; }; pkill -f "[w]rangler dev" 2>/dev/null || true; pkill -x workerd 2>/dev/null || true; sleep 1; echo stopped;;
  status) curl -s http://127.0.0.1:8787/_worker/mem; echo;;
esac
