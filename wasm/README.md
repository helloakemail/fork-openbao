# OpenBao on Cloudflare Workers (experimental js/wasm build)

This directory holds an experiment: compile the OpenBao core to WebAssembly
with the standard Go toolchain (`GOOS=js GOARCH=wasm`) and run it inside a
Cloudflare Worker, stateless, with PostgreSQL (through Hyperdrive) as the
only storage backend and the `static` seal for hands-off auto-unseal.

Status: **it runs.** Under workerd (`wrangler dev`) against PostgreSQL, the core
initialises, auto-unseals from the static seal, and passes a black-box API
suite covering kv, policies and tokens, userpass, AppRole, JWT, transit, PKI,
the database engine and TTL expiry, three runs in a row, with flat memory
(67 MB of linear memory, 128 MB limit). Size after the first round of feature
removals is 67.2 MB after wasm-opt against Cloudflare's 64 MiB (67.1 MB)
uncompressed limit: 48 KB over, with the grpc/go-plugin removal still in
progress. Nothing has been deployed to Cloudflare itself yet.
Everything below is measured in this tree unless marked as an estimate.

## Layout

| Path | What |
|---|---|
| `worker/main.go` | Worker entrypoint: builds the PostgreSQL backend over Cloudflare TCP sockets, the static auto-seal, `vault.NewCore`, and serves OpenBao's regular `http.Handler` through `workers-go`. |
| `worker/registry_full.go`, `worker/registry_lean.go` | Builtin plugin registry. Default is the full OpenBao set; `-tags baolean` swaps in a reduced set (approle, cert, jwt/oidc, userpass; kv, pki, ssh, totp, transit; postgresql database plugin). |
| `worker/loader/worker.mjs` | JS loader: a Durable Object class (`OpenBaoCore`) hosting **one long-lived Go instance**, plus a stateless Worker that forwards every request to the single object. |
| `acceptance/` | Black-box API suite (`go test -tags acceptance`) that runs against any `BAO_ADDR`: native binary or the Worker. |
| `harness/` | `build.sh` (wasm build + wasm-opt + size log), `workerd.sh` (wrangler dev), `memprobe.sh`, `reset-db.sh`, native baseline server config. |
| `third_party/workers-go` | Vendored `syumai/workers-go` v0.36.0 with the `js.Func` leaks fixed (see below); wired in with a `replace`. |
| `worker/wrangler.jsonc`, `worker/package.json` | Wrangler config and build script. |
| `sizeprobe/` | Native twin of the worker used to attribute binary size per package (`go tool nm` cannot read Go wasm). |
| `go_js_wasm_exec_clean` | `go test -exec` wrapper so js/wasm test binaries run under Node despite a large environment. |
| `third_party/mlock` | Verbatim copy of `hashicorp/go-secure-stdlib/mlock` with `js`/`wasip1` added to the "unavailable" build tags; wired in with a `replace` in the root `go.mod`. |

Changes outside this directory (all behind `//go:build js` / `!js`, native
builds unchanged):

- `internal/physical/raft`: every hand-written file tagged `!js` (the generated `types.pb.go` is left alone, it compiles anywhere); `raft_js.go` keeps the exported data types and stubs every `RaftBackend` method with a "not supported" error. Raft needs disk, mmap and bbolt, none of which exist in wasm.
- `internal/physical/pebbledb`: tagged `!js`; `internal/physical/inmem` gets its pebble dependency through a two-file split.
- `internal/vault/raft_discover*.go`: `hashicorp/go-discover` (raft auto-join) moved behind a one-method interface and excluded on js. This alone halves the wasm.
- `internal/helper/configutil/telemetry_stackdriver*.go`: the Google Cloud Monitoring sink split out and excluded on js.
- `internal/physical/postgresql/testing.go`: tagged `!js` (it is a non-test file that imports the Docker test helpers).
- `sdk/database/helper/connutil`: an `OpenHook` so the Worker can route the database engine's own `sql.Open("pgx", …)` through Cloudflare sockets. Nil on native builds.

## Build

```sh
# core packages, any target
GOOS=js GOARCH=wasm go build -tags hashicorpmetrics ./internal/vault ./internal/http ./internal/physical/postgresql

# the Worker (lean registry recommended)
GOOS=js GOARCH=wasm go build -tags "hashicorpmetrics baolean" -ldflags="-s -w" -o wasm/worker/build/app.wasm ./wasm/worker

# or, from wasm/worker, generate the JS glue and build in one go
npm run build
```

`-tags hashicorpmetrics` is required: it routes `hashicorp/go-metrics/compat`
to the maintained `hashicorp/go-metrics`, which has a `js` constant file; the
legacy `armon/go-metrics` references `syscall.SIGUSR1` and does not compile.

## How it is wired

1. **A Durable Object hosts the core.** A plain Worker cannot: every socket
   and timer belongs to the request that created it, so OpenBao's background
   goroutines (kv v2's post-mount upgrade, lease expiry, the rollback
   manager) stall the moment their request returns. The `/_worker/bg`
   experiment shows a goroutine stuck at "dialing" forever in Worker mode and
   finishing in under a second inside a Durable Object, whose context lives
   on while outbound sockets are open (up to 15 minutes per socket, per the
   June 2026 changelog). A single object (`idFromName("singleton")`) also
   gives single-writer semantics for free.
2. **Lifecycle.** The object starts the Go program once (`ServeNonBlock`,
   `Ready`, then block forever) and keeps it. The core is built lazily on
   the first request, since bindings and sockets are only reachable from a
   request context, and auto-unseals when storage is already initialised.
   First boot of a fresh database is `POST /v1/sys/init` as usual; the root
   key is stored wrapped by the static key, so later cold starts unseal
   themselves.
3. **PostgreSQL.** `pgx.ParseConfig` on the Hyperdrive binding's
   `connectionString` (or `BAO_PG_CONNECTION_URL`) with `DialFunc` routed to
   `cloudflare:sockets` `connect()` and `LookupFunc` short-circuited (no DNS
   in the sandbox). The config is registered with `stdlib.RegisterConnConfig`
   so OpenBao's unmodified backend can `sql.Open("pgx", name)` it. The
   database secrets engine's plugin goes through the same path via
   `connutil.OpenHook`. Locally, wrangler's Hyperdrive emulation hands the
   Worker `postgres://…@<id>.hyperdrive.local:5432/…`, and a raw-socket probe
   confirmed Postgres answers on it.
4. **Seal and core config.** `go-kms-wrapping/wrappers/static` from the
   `BAO_STATIC_SEAL_CURRENT_KEY` secret in `vault.NewAutoSeal`;
   `DisableCache: true`, no HA backend, `DisableSSCTokens: true`, only the
   `http` audit backend.
5. **Worker-specific fixes.** workers-go leaves `Request.Body` nil on
   body-less requests where net/http guarantees `http.NoBody`; the handler
   normalises it. The vendored workers-go releases the `js.Func` callbacks
   it allocated per promise await, per stream read and per response body;
   with one long-lived instance those leaked about 1 MB per kv mount cycle.
6. **Debug routes** (only with `BAO_WORKER_DEBUG` set): `/_worker/mem`
   (linear memory and Go `MemStats`), `/_worker/heap` (pprof),
   `/_worker/goroutines` (histogram), `/_worker/pgping`, `/_worker/bg`.

## Running it locally

```sh
wasm/harness/build.sh                 # wasm + wasm-opt into wasm/worker/build (add --no-opt while iterating)
cp wasm/worker/loader/worker.mjs wasm/worker/build/worker.mjs
wasm/harness/workerd.sh start         # wrangler dev on :8787, local Postgres via Hyperdrive's localConnectionString
BAO_ADDR=http://127.0.0.1:8787 BAO_ACCEPT_PG_URL='postgres://bao:bao@127.0.0.1:5432/bao?sslmode=disable' \
  go test -tags acceptance -count=1 -v ./wasm/acceptance
wasm/harness/memprobe.sh              # linear / sys / heap in MB
```

`wasm/worker/.dev.vars` (not committed) holds the static seal key for local
dev; `wasm/harness/native-server.sh` runs the native binary with the same
storage and seal for baselining the suite.

## Measured memory

Linear memory is what counts against the 128 MB isolate limit (plus the JS
heap). Go's `MemStats.Sys` excludes the 44.5 MB data segment, so the probe
reads `WebAssembly.Memory.buffer.byteLength` directly.

| Point | Linear memory | Go heap after GC |
|---|---|---|
| Go started, no core | 54.5 MB | 2 MB |
| Core built, unsealed | 63 MB | 4 MB |
| After the full acceptance suite, run 1 / 2 / 3 | 66.6 / 67.1 / 67.1 MB | 5.3 / 5.5 / 5.6 MB |
| Before the workers-go leak fix, runs 1 / 2 / 3 | 71 / 78 / 83 MB | 8.3 / 10.7 / 13.4 MB |

Goroutines sit at 523: 500 are the expiration manager's fair-share workers,
a tunable. The data segment shrinks with every size removal, so memory is
not the limiting resource.

## Measured sizes

All with Go 1.27.0, `-ldflags="-s -w"`.

| Build | Uncompressed | gzip -9 |
|---|---|---|
| Native linux/amd64, full CLI | 127 MB | |
| Worker wasm, full plugin registry | 224 MB | 35 MB |
| Worker wasm, `baolean` registry | 204 MB | 33 MB |
| Worker wasm, `baolean` + go-discover excluded | 106 MB | 20 MB |
| Same, after `wasm-opt -Oz` (binaryen 123, 3.5 min, 7.5 CPU-min) | 93 MB | 20 MB |
| + CEL engine and Google Workspace provider excluded | 89.3 MB raw | |
| + ACME listener TLS, OCI download, KMIP seal, Okta/Duo/PingID MFA, Prometheus/Datadog/Circonus sinks, test helpers, PGP excluded (current tree) | 75.8 MB raw / **67.2 MB opt** | 14.8 MB |
| **Cloudflare limit (uncompressed, Free and Paid)** | **64 MiB = 67 MB** | no compressed limit |

Section breakdown of the 204 MB build: code 115 MB, data 88 MB (Go's
pclntab and rodata; `-w` already dropped DWARF). `GOWASM=satconv,signext`
made no measurable difference.

## Back-of-the-envelope model (and how it checks out)

Inputs from the native build of the lean worker twin (`wasm/sizeprobe`):

| Quantity | Value |
|---|---|
| `.text` | 48.9 MB |
| `.gopclntab` | 38.2 MB (0.78 × text) |
| `.rodata` + `.data` + `.noptrdata` | 4.9 MB |
| Non-bss symbol bytes (`go tool nm -size`, ≈ text+rodata+data) | 54.0 MB |

Ratios:

- Native non-bss bytes ≈ 1.8 × symbol bytes (pclntab rides along with text).
- Go's wasm backend is a stack machine with every Go local spilled to linear
  memory, plus larger PC tables: measured code 115 MB vs text 49 MB (2.35×)
  and data 88 MB vs 43 MB (2.05×), so wasm ≈ 2.2 × native non-bss.
- Net: **wasm bytes ≈ 3.8 × symbol bytes.**

Checks: 54 MB × 3.8 = 205 MB predicted vs 204 MB measured. After excluding
go-discover, the packages left in the js build sum to 24.8 MB of native
symbols, predicting 94 MB vs 106 MB measured (the k8s/protobuf-heavy
packages that left were lighter than average per symbol byte).

What is left in the 106 MB, by native symbol bytes (biggest first):
`internal/vault` 2.5 MB, `internal/builtin` (the lean plugin set) 1.9 MB,
Go std ≈ 6.7 MB (crypto 1.4, net 0.9, runtime 0.9, encoding 0.6, ...),
`pgx` 1.1 MB, protobuf + grpc + go-plugin ≈ 1.5 MB, cel-go + antlr ≈ 1.5 MB,
`google.golang.org/api/admin` 0.5 MB (jwt auth Google groups),
`okta-sdk` 0.3 MB (login MFA), `kmip-go` + certmagic + miekg/dns ≈ 1 MB
(KMIP seal client), x/text 0.55 MB, circl 0.45 MB, go-jose 0.3 MB.

To fit 67 MB the budget is ≈ 17.5 MB of symbol bytes, i.e. another ~7 MB
has to go on top of the current 24.8 MB. There is no dependency left that
large; the candidates are OpenBao features: CEL roles (~1.5 MB), external
plugin support and request forwarding (grpc/go-plugin, ~2 MB), the Okta and
Google MFA/group integrations (~0.8 MB), the KMIP seal client (~1 MB), plus
the 13% that `wasm-opt -Oz` recovers (106 MB to 93 MB, measured). The
estimate therefore says a "core-only" OpenBao lands around the limit, not
comfortably under it, and only after removing features, not just
dependencies.

## Other constraints found (not size)

- **Cold start.** workerd compiles the 93 MB module on first load (8 to 25 s
  observed locally; Cloudflare precompiles at deploy time) and the first
  request then builds the core and unseals (about 1.8 s against local
  Postgres). Later requests are tens of milliseconds.
- **Connections.** Every storage operation currently dials a new socket
  (`max_idle_connections=0`, chosen for plain-Worker semantics). Inside the
  Durable Object sockets persist, so a small idle pool is the next
  optimisation.
- **Concurrency.** One Durable Object instance serialises everything, which
  matches OpenBao's single-active-node model but caps throughput at that one
  object; it also lives in one location.
- **Wall clock.** Workers only advance `Date.now()` on I/O, so `time.Now()`
  is coarse inside a request.
- **Not yet exercised on Cloudflare itself.** workerd locally does not
  enforce the 128 MB memory limit or the CPU limit; the numbers above come
  from the Worker's own reporting.

## Practical alternatives

- **Cloudflare Containers** (Durable Object + container, GA 2025): run the
  unmodified linux OpenBao binary with the same PostgreSQL/Hyperdrive
  setup. Removes the size, memory, background-goroutine and raft problems at
  once; keeps the Worker as the edge front door.
- **OpenBao-lite build tag**: continue the surgery above (CEL, go-plugin /
  grpc, MFA providers, KMIP) behind a `baolean`-style tag until the wasm is
  under 64 MiB, then test on a Paid plan with `limits.cpu_ms` raised.

## Reproducing the measurements

```sh
S=/tmp/sizes; mkdir -p $S
GOOS=js GOARCH=wasm go build -tags "hashicorpmetrics baolean" -ldflags="-s -w" -o $S/worker.wasm ./wasm/worker
ls -l $S/worker.wasm

go build -ldflags="-s -w" -o $S/probe ./wasm/sizeprobe && readelf -S -W $S/probe   # section sizes
go build -o $S/probe-syms ./wasm/sizeprobe && go tool nm -size $S/probe-syms        # per-symbol sizes
GOOS=js GOARCH=wasm go list -tags "hashicorpmetrics baolean" -deps ./wasm/worker     # what is in the wasm
```
