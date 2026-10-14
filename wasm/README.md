# OpenBao on Cloudflare Workers (experimental js/wasm build)

This directory holds an experiment: compile the OpenBao core to WebAssembly
with the standard Go toolchain (`GOOS=js GOARCH=wasm`) and run it inside a
Cloudflare Worker, stateless, with PostgreSQL (through Hyperdrive) as the
only storage backend and the `static` seal for hands-off auto-unseal.

Status in one line: **it compiles and links, the Worker entrypoint is written,
but the binary is still ~1.6x over Cloudflare's 64 MiB uncompressed size limit
and nothing has been executed on Cloudflare yet.** Everything below is
measured in this tree unless marked as an estimate.

## Layout

| Path | What |
|---|---|
| `worker/main.go` | Worker entrypoint: builds the PostgreSQL backend over Cloudflare TCP sockets, the static auto-seal, `vault.NewCore`, and serves OpenBao's regular `http.Handler` through `workers-go`. |
| `worker/registry_full.go`, `worker/registry_lean.go` | Builtin plugin registry. Default is the full OpenBao set; `-tags baolean` swaps in a reduced set (approle, cert, jwt/oidc, userpass; kv, pki, ssh, totp, transit; postgresql database plugin). |
| `worker/loader/worker.mjs` | JS loader. Modified from the `workers-go` generated one so a Go instance is started **once per isolate** instead of once per request. |
| `worker/wrangler.jsonc`, `worker/package.json` | Wrangler config and build script. |
| `sizeprobe/` | Native twin of the worker used to attribute binary size per package (`go tool nm` cannot read Go wasm). |
| `third_party/mlock` | Verbatim copy of `hashicorp/go-secure-stdlib/mlock` with `js`/`wasip1` added to the "unavailable" build tags; wired in with a `replace` in the root `go.mod`. |

Changes outside this directory (all behind `//go:build js` / `!js`, native
builds unchanged):

- `internal/physical/raft`: every hand-written file tagged `!js` (the generated `types.pb.go` is left alone, it compiles anywhere); `raft_js.go` keeps the exported data types and stubs every `RaftBackend` method with a "not supported" error. Raft needs disk, mmap and bbolt, none of which exist in wasm.
- `internal/physical/pebbledb`: tagged `!js`; `internal/physical/inmem` gets its pebble dependency through a two-file split.
- `internal/vault/raft_discover*.go`: `hashicorp/go-discover` (raft auto-join) moved behind a one-method interface and excluded on js. This alone halves the wasm.
- `internal/helper/configutil/telemetry_stackdriver*.go`: the Google Cloud Monitoring sink split out and excluded on js.
- `internal/physical/postgresql/testing.go`: tagged `!js` (it is a non-test file that imports the Docker test helpers).

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

## How the Worker is wired

1. **Lifecycle.** A Worker cannot open sockets or read bindings in global
   scope, so `main()` only registers the handler. On the first request the
   handler builds the backend, seal and core, then auto-unseals if storage is
   already initialised. First boot of a fresh database is done by calling
   `POST /v1/sys/init` as usual; with an auto-seal the root key is stored in
   PostgreSQL wrapped by the static key, so every later cold start unseals
   itself.
2. **PostgreSQL.** `pgx.ParseConfig` on the Hyperdrive binding's
   `connectionString` (or `BAO_PG_CONNECTION_URL`), with `DialFunc`
   replaced by `workers-go/cloudflare/sockets.Connect` (Cloudflare's
   `connect()` API) and `LookupFunc` short-circuited because there is no DNS
   resolver in the sandbox. The config is registered with
   `stdlib.RegisterConnConfig` so OpenBao's unmodified PostgreSQL backend
   can `sql.Open("pgx", name)` it. `max_idle_connections` defaults to 0
   because Cloudflare closes sockets when the request that opened them ends.
   Hyperdrive lists `rust-postgres` (a raw-socket client) as supported, so a
   Go client over `connect()` is expected to work, but this is unverified.
3. **Seal.** `go-kms-wrapping/wrappers/static` with the key from the
   `BAO_STATIC_SEAL_CURRENT_KEY` Worker secret, wrapped in `vault.NewAutoSeal`.
4. **Core config.** `DisableCache: true` (several isolates may serve the same
   database concurrently with no leader election, so an in-memory cache can
   be stale), no HA backend, `DisableSSCTokens: true`, only the `http` audit
   backend (file/syslog/socket cannot work in a Worker).
5. **Loader.** `workers-go` instantiates a new Go program per request. That
   is fine for a hello-world but would redo unseal and mount setup (dozens of
   PostgreSQL round-trips) on every request, so `loader/worker.mjs` starts
   Go once per isolate and reuses it. The core then lives as long as
   Cloudflare keeps the isolate alive.

## Measured sizes

All with Go 1.27.0, `-ldflags="-s -w"`.

| Build | Uncompressed | gzip -9 |
|---|---|---|
| Native linux/amd64, full CLI | 127 MB | |
| Worker wasm, full plugin registry | 224 MB | 35 MB |
| Worker wasm, `baolean` registry | 204 MB | 33 MB |
| Worker wasm, `baolean` + go-discover excluded (current tree) | **106 MB** | 20 MB |
| Same, after `wasm-opt -Oz` (binaryen 123) | not yet measured | |
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
whatever `wasm-opt -Oz` recovers (typically 10–15% on Go output). The
estimate therefore says a "core-only" OpenBao lands around the limit, not
comfortably under it, and only after removing features, not just
dependencies.

## Other constraints found (not size)

- **Runtime instantiation.** With the stock `workers-go` loader every
  request re-runs `main()`, unseal and mount setup. The custom loader fixes
  that but the first request on each new isolate still pays a full cold
  start: Go runtime init of a ~100 MB module plus unseal (barrier keyring,
  mount table, policies, token store, audit setup) over the network to
  PostgreSQL. Expect seconds, not milliseconds; it counts against the 30 s
  default CPU limit only for the CPU part.
- **Memory.** Isolates get 128 MB. Go's wasm linear memory has to hold the
  data section (≈ 45 MB at the current size) plus the heap. Not measured.
- **Background work.** OpenBao relies on long-running goroutines
  (expiration manager, rollback manager, periodic funcs, lease revocation).
  Workers run no code between requests and may be evicted any time, so lease
  expiry and tidy work must be driven externally, e.g. a Cron Trigger that
  hits an endpoint. Not implemented.
- **Concurrency and consistency.** No HA, no leader election: every isolate
  believes it is the active node. The PostgreSQL backend's transactions keep
  individual operations consistent, and `DisableCache` avoids stale reads,
  but concurrent isolates mutating shared state (mount table, policies,
  rotations) is a mode OpenBao was not designed for.
- **Sockets.** One socket per request lifetime, six simultaneous outbound
  connections per Worker, DNS only via `connect()`. TLS to a non-Hyperdrive
  database would be pure-Go `crypto/tls` inside wasm.
- **Wall clock.** Workers only advance `Date.now()` on I/O, so `time.Now()`
  is coarse inside a request. Token TTL math still works; timing-based
  code paths are less predictable.
- **Nothing is tested on Cloudflare.** No account or `wrangler` in this
  environment; the loader, bindings and Hyperdrive dial path are written
  against the documented APIs only.

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
