#!/usr/bin/env bash
# Build the Worker wasm, optionally run wasm-opt, and record sizes.
#
#   wasm/harness/build.sh [-t "extra build tags"] [-o out.wasm] [--no-opt]
#
# Env: WASM_OPT (path to binaryen's wasm-opt; auto-detected on PATH).
# Appends a row to wasm/harness/results.csv: utc time, git sha, tags, raw bytes, opt bytes, gzip bytes.
set -euo pipefail
cd "$(dirname "$0")/../.."
TAGS="hashicorpmetrics baolean"; OUT="wasm/worker/build/app.wasm"; OPT=1
while [ $# -gt 0 ]; do case "$1" in
  -t) TAGS="$TAGS $2"; shift 2;;
  -o) OUT="$2"; shift 2;;
  --no-opt) OPT=0; shift;;
  *) echo "unknown arg $1" >&2; exit 2;;
esac; done
mkdir -p "$(dirname "$OUT")"
GOOS=js GOARCH=wasm go build -tags "$TAGS" -ldflags="-s -w" -o "$OUT.raw" ./wasm/worker
RAW=$(stat -c %s "$OUT.raw")
WASM_OPT="${WASM_OPT:-$(command -v wasm-opt || true)}"
if [ "$OPT" = 1 ] && [ -n "$WASM_OPT" ]; then
  "$WASM_OPT" -Oz --enable-bulk-memory --enable-sign-ext --enable-nontrapping-float-to-int \
    --enable-mutable-globals --enable-multivalue --enable-reference-types "$OUT.raw" -o "$OUT"
else
  cp "$OUT.raw" "$OUT"
fi
OPTB=$(stat -c %s "$OUT")
GZ=$(gzip -9 -c "$OUT" | wc -c)
SHA=$(git rev-parse --short HEAD)
printf '%s,%s,"%s",%s,%s,%s\n' "$(date -u +%FT%TZ)" "$SHA" "$TAGS" "$RAW" "$OPTB" "$GZ" >> wasm/harness/results.csv
printf 'raw %.1f MB  opt %.1f MB  gzip %.1f MB  (limit 67.1 MB; over by %.1f MB)\n' \
  "$(echo "$RAW/1000000" | bc -l)" "$(echo "$OPTB/1000000" | bc -l)" "$(echo "$GZ/1000000" | bc -l)" "$(echo "($OPTB-67108864)/1000000" | bc -l)"
