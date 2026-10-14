#!/usr/bin/env bash
# Print Go runtime memory (MB) from the Worker's debug endpoint.
#   wasm/harness/memprobe.sh [label] [addr]
ADDR="${2:-http://127.0.0.1:8787}"
printf '%-28s ' "${1:-mem}"; OUT=$(curl -s "$ADDR/_worker/mem?gc=1"); echo "$OUT" | python3 -c 'import sys,json
raw=sys.stdin.read()
try: m=json.loads(raw)
except Exception: print("not json:", raw[:200].replace("\n"," ")); sys.exit(0)
print("sys %.1f  heap_sys %.1f  heap_inuse %.1f  heap_alloc %.1f  stack %.1f  goroutines %d  gc %d  sealed %s" % (m["sys_mb"],m["heap_sys_mb"],m["heap_inuse_mb"],m["heap_alloc_mb"],m["stack_sys_mb"],m["num_goroutine"],m["num_gc"],m["sealed"]))'
