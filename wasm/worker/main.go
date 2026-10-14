// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js && wasm

// Command worker is an experimental Cloudflare Workers entrypoint for the
// OpenBao core compiled to WebAssembly (GOOS=js GOARCH=wasm).
//
// It is deliberately stateless: every piece of persistent state lives in
// PostgreSQL (reached through Cloudflare's TCP socket API, normally via a
// Hyperdrive binding) and the barrier is auto-unsealed with the "static" seal
// whose key is supplied as a Worker secret.
//
// Lifecycle: a Worker cannot open sockets or read bindings in global scope, so
// the core is built lazily on the first request handled by a given Go
// instance. See wasm/README.md for the loader and its implications.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	log "github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	static "github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/openbao/sdk/v2/database/helper/connutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/audit"
	auditHttp "github.com/openbao/openbao/v2/internal/builtin/audit/http"
	logicalDb "github.com/openbao/openbao/v2/internal/builtin/logical/database"
	logicalKv "github.com/openbao/openbao/v2/internal/builtin/logical/kv"
	"github.com/openbao/openbao/v2/internal/builtin/plugin"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/physical/postgresql"
	"github.com/openbao/openbao/v2/internal/vault"
	vaultseal "github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/syumai/workers-go"
	"github.com/syumai/workers-go/cloudflare"
	"github.com/syumai/workers-go/cloudflare/sockets"
)

// Environment variables / secrets read from the Worker's bindings.
const (
	envHyperdriveBinding = "BAO_HYPERDRIVE_BINDING" // name of a Hyperdrive binding (default "HYPERDRIVE")
	envConnectionURL     = "BAO_PG_CONNECTION_URL"  // used when no Hyperdrive binding is present
	envTable             = "BAO_PG_TABLE"
	envMaxIdleConns      = "BAO_PG_MAX_IDLE_CONNECTIONS"
	envSealKey           = static.EnvBaoCurrentKeyValueName      // BAO_STATIC_SEAL_CURRENT_KEY
	envSealKeyID         = static.EnvBaoCurrentKeyIdentifierName // BAO_STATIC_SEAL_CURRENT_KEY_ID
	envPrevSealKey       = static.EnvBaoPreviousKeyValueName
	envPrevSealKeyID     = static.EnvBaoPreviousKeyIdentifierName
	envLogLevel          = "BAO_LOG_LEVEL"
	envAPIAddr           = "BAO_API_ADDR"
)

var bgState = func() *atomic.Value { v := &atomic.Value{}; v.Store("idle"); return v }()

type server struct {
	mu         sync.Mutex
	runtimeCtx context.Context // first request's context, carries the workers-go runtime context
	core       *vault.Core
	handler    http.Handler
	logger     log.Logger
}

func main() {
	s := &server{}
	// Database secrets engine plugins open their own connections; route the
	// PostgreSQL plugin through Cloudflare sockets as well.
	connutil.OpenHook = func(driver, dsn string) (string, string, error) {
		if driver != "pgx" {
			return driver, dsn, fmt.Errorf("database driver %q is not supported on the Worker build", driver)
		}
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return "", "", err
		}
		applyWorkerDialer(cfg, s.dialCtx())
		return "pgx", stdlib.RegisterConnConfig(cfg), nil
	}
	// workers.Serve would return (and the Go program exit) as soon as the first
	// response body is closed. The loader keeps one Go instance per isolate,
	// so register the handler, signal readiness and then block forever.
	workers.ServeNonBlock(s)
	workers.Ready()
	select {}
}

// ServeHTTP lazily builds the core on the first request (bindings and
// sockets are only reachable from a request context), auto-unseals it when
// storage is already initialised, then hands off to the regular OpenBao HTTP
// handler.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if p := recover(); p != nil {
			msg := fmt.Sprintf("openbao worker: panic serving %s %s: %v\n%s", r.Method, r.URL.Path, p, debug.Stack())
			consoleError(msg)
			http.Error(w, msg, http.StatusInternalServerError)
		}
	}()
	// workers-go leaves Body nil on body-less requests; net/http's server
	// never does, and OpenBao's request-size wrapper relies on that.
	if r.Body == nil {
		r.Body = http.NoBody
	}
	if strings.HasPrefix(r.URL.Path, "/_worker/") {
		s.serveDebug(w, r)
		return
	}
	if err := s.ensureCore(r.Context()); err != nil {
		http.Error(w, "openbao worker: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if s.core.Sealed() {
		// Until someone has called sys/init there is nothing to unseal with;
		// the init request itself goes through the normal handler below.
		if initialized, err := s.core.Initialized(r.Context()); err == nil && initialized {
			if err := s.core.UnsealWithStoredKeys(r.Context()); err != nil {
				s.logger.Error("auto-unseal failed", "error", err)
			}
		}
	}
	s.handler.ServeHTTP(w, r)
}

func (s *server) ensureCore(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core != nil {
		return nil
	}
	s.runtimeCtx = context.WithoutCancel(ctx)

	level := cloudflare.Getenv(envLogLevel)
	if level == "" {
		level = "info"
	}
	logger := log.New(&log.LoggerOptions{
		Name:   "openbao-worker",
		Level:  log.LevelFromString(level),
		Output: os.Stderr, // wasm_exec.js forwards this to console
	})
	s.logger = logger

	backend, err := newPostgresBackend(ctx, logger)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}

	seal, err := newStaticSeal(ctx)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	coreConfig := &vault.CoreConfig{
		Physical:    backend,
		StorageType: "postgresql",
		Seal:        seal,
		Logger:      logger,
		LogLevel:    level,
		// A Worker isolate can be evicted at any time and several isolates
		// may serve the same storage concurrently without any leader
		// election, so never trust an in-memory cache across requests.
		DisableCache: true,
		// No cluster port is ever listened on; this only has to be non-empty.
		RedirectAddr:       apiAddr(),
		AuditBackends:      map[string]audit.Factory{"http": auditHttp.Factory},
		CredentialBackends: map[string]logical.Factory{"plugin": plugin.Factory},
		LogicalBackends: map[string]logical.Factory{
			"plugin":   plugin.Factory,
			"database": logicalDb.Factory,
			"kv":       logicalKv.Factory,
		},
		BuiltinRegistry:  pluginRegistry,
		DisableSSCTokens: true,
		// sys/metrics dereferences the helper unconditionally; give it an
		// in-memory sink (no Prometheus on this build).
		MetricsHelper: metricsutil.NewMetricsHelper(metrics.NewInmemSink(10*time.Second, time.Minute), false),
	}

	core, err := vault.NewCore(coreConfig)
	if err != nil && vault.IsFatalError(err) {
		return fmt.Errorf("core: %w", err)
	}
	if err != nil {
		logger.Warn("non-fatal error creating core", "error", err)
	}

	s.core = core
	s.handler = vaulthttp.Handler.Handler(&vault.HandlerProperties{
		Core:           core,
		ListenerConfig: &configutil.Listener{Type: "tcp", Address: "worker"},
	})
	return nil
}

// newPostgresBackend wires OpenBao's PostgreSQL physical backend to a pgx
// driver whose connections are Cloudflare TCP sockets. Hyperdrive hands the
// Worker a per-deployment connection string through its binding; a plain
// BAO_PG_CONNECTION_URL works too (TLS is then done in pure Go by pgx).
func newPostgresBackend(ctx context.Context, logger log.Logger) (*postgresql.PostgreSQLBackend, error) {
	cfg, err := pgxConfig(ctx)
	if err != nil {
		return nil, err
	}
	name := stdlib.RegisterConnConfig(cfg)

	conf := map[string]string{
		"connection_url": name,
		// The core runs inside a Durable Object, where outbound sockets
		// outlive the request that opened them, so a small idle pool is safe
		// and cuts the acceptance suite's wall time by 40%. Hyperdrive holds
		// the real pool to the database.
		"max_idle_connections": "4",
		"max_connect_retries":  "1",
		"ha_enabled":           "false",
	}
	if v := cloudflare.Getenv(envTable); v != "" {
		conf["table"] = v
	}
	if v := cloudflare.Getenv(envMaxIdleConns); v != "" {
		conf["max_idle_connections"] = v
	}

	b, err := postgresql.NewPostgreSQLBackend(conf, logger)
	if err != nil {
		return nil, err
	}
	return b.(*postgresql.PostgreSQLBackend), nil
}

// pgxConfig builds the pgx connection config from the Hyperdrive binding (or
// BAO_PG_CONNECTION_URL) with dialing routed through Cloudflare sockets.
func pgxConfig(ctx context.Context) (*pgx.ConnConfig, error) {
	bindingName := cloudflare.Getenv(envHyperdriveBinding)
	if bindingName == "" {
		bindingName = "HYPERDRIVE"
	}
	connURL := ""
	if b := cloudflare.GetBinding(bindingName); !b.IsUndefined() && !b.IsNull() {
		connURL = b.Get("connectionString").String()
	}
	if connURL == "" {
		connURL = cloudflare.Getenv(envConnectionURL)
	}
	if connURL == "" {
		return nil, fmt.Errorf("neither Hyperdrive binding %q nor %s is set", bindingName, envConnectionURL)
	}

	cfg, err := pgx.ParseConfig(connURL)
	if err != nil {
		return nil, fmt.Errorf("parsing connection url: %w", err)
	}
	applyWorkerDialer(cfg, ctx)
	return cfg, nil
}

// applyWorkerDialer makes a pgx config dial through Cloudflare's connect()
// API. dialCtx must carry the workers-go runtime context (any request
// context does); connect() is unreachable from a plain context.
func applyWorkerDialer(cfg *pgx.ConnConfig, dialCtx context.Context) {
	// Workers have no DNS resolver available to Go; connect() resolves names
	// itself (and recognises Hyperdrive hosts).
	cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) {
		return []string{host}, nil
	}
	cfg.DialFunc = func(_ context.Context, network, addr string) (net.Conn, error) {
		return sockets.Connect(dialCtx, addr, &sockets.SocketOptions{
			SecureTransport: sockets.SecureTransportOff,
		})
	}
	cfg.ConnectTimeout = 10 * time.Second
}

// dialCtx returns a context that carries the runtime context captured from the
// request that built the core; it is only valid once ensureCore has run.
func (s *server) dialCtx() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeCtx == nil {
		return context.Background()
	}
	return s.runtimeCtx
}

func consoleError(msg string) {
	js.Global().Get("console").Call("error", msg)
}

// newStaticSeal builds an auto-seal from the static-key wrapper so that the
// barrier can be unsealed on every cold start without a human.
func newStaticSeal(ctx context.Context) (vault.Seal, error) {
	key := cloudflare.Getenv(envSealKey)
	if key == "" {
		return nil, errors.New(envSealKey + " secret is not set")
	}
	keyID := cloudflare.Getenv(envSealKeyID)
	if keyID == "" {
		keyID = "worker"
	}
	opts := []wrapping.Option{
		static.WithCurrentKey(key),
		static.WithCurrentKeyId(keyID),
	}
	if prev := cloudflare.Getenv(envPrevSealKey); prev != "" {
		opts = append(opts, static.WithPreviousKey(prev))
		prevID := cloudflare.Getenv(envPrevSealKeyID)
		if prevID == "" {
			prevID = "worker-previous"
		}
		opts = append(opts, static.WithPreviousKeyId(prevID))
	}
	wrapper := static.NewWrapper()
	if _, err := wrapper.SetConfig(ctx, opts...); err != nil {
		return nil, err
	}
	seal, err := vault.NewAutoSeal(vaultseal.NewAccess(wrapper))
	if err != nil {
		return nil, err
	}
	return seal, nil
}

// serveDebug exposes Go runtime memory statistics for the harness. Only
// enabled when the BAO_WORKER_DEBUG variable is set; MemStats.Sys is the size
// of the wasm linear memory Go has reserved, which is what counts against the
// Worker's 128 MB isolate limit (plus the JS heap).
func (s *server) serveDebug(w http.ResponseWriter, r *http.Request) {
	if cloudflare.Getenv("BAO_WORKER_DEBUG") == "" {
		http.NotFound(w, r)
		return
	}
	switch r.URL.Path {
	case "/_worker/pgping":
		start := time.Now()
		cfg, err := pgxConfig(r.Context())
		if err == nil {
			var conn *pgx.Conn
			conn, err = pgx.ConnectConfig(r.Context(), cfg)
			if err == nil {
				err = conn.Ping(r.Context())
				conn.Close(r.Context())
			}
		}
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"ms": time.Since(start).Milliseconds(), "host": "", "ok": err == nil}
		if cfg != nil {
			out["host"] = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
		}
		if err != nil {
			out["error"] = err.Error()
		}
		json.NewEncoder(w).Encode(out)
	case "/_worker/bg":
		// Experiment: does a goroutine that performs socket I/O after this
		// request has returned still make progress? Start it, return at once,
		// then poll /_worker/bg?status=1.
		if r.URL.Query().Get("status") != "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"bg": bgState.Load()})
			return
		}
		bgState.Store("started")
		go func() {
			time.Sleep(500 * time.Millisecond)
			bgState.Store("slept")
			cfg, err := pgxConfig(s.dialCtx())
			if err != nil {
				bgState.Store("config error: " + err.Error())
				return
			}
			bgState.Store("dialing")
			conn, err := pgx.ConnectConfig(context.Background(), cfg)
			if err != nil {
				bgState.Store("dial error: " + err.Error())
				return
			}
			bgState.Store("connected")
			var one int
			if err := conn.QueryRow(context.Background(), "select 1").Scan(&one); err != nil {
				bgState.Store("query error: " + err.Error())
				return
			}
			conn.Close(context.Background())
			bgState.Store("done")
		}()
		w.Write([]byte("started\n"))
	case "/_worker/heap":
		// pprof heap profile (inuse after a forced GC); analyse natively with
		// `go tool pprof -sample_index=inuse_space -top heap.pb.gz`.
		runtime.GC()
		w.Header().Set("Content-Type", "application/octet-stream")
		pprof.Lookup("heap").WriteTo(w, 0)
	case "/_worker/goroutines":
		// Histogram of goroutines by their top non-runtime frame, to spot leaks.
		buf := make([]byte, 1<<22)
		n := runtime.Stack(buf, true)
		counts := map[string]int{}
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			lines := strings.Split(g, "\n")
			top := "?"
			for i := 1; i+1 < len(lines); i += 2 {
				if !strings.HasPrefix(lines[i], "runtime.") && !strings.HasPrefix(lines[i], "sync.") && !strings.HasPrefix(lines[i], "syscall/js.") {
					top = lines[i]
					break
				}
			}
			counts[top]++
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"total": runtime.NumGoroutine(), "by_frame": counts})
	case "/_worker/mem":
		if r.URL.Query().Get("gc") != "" {
			runtime.GC()
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		w.Header().Set("Content-Type", "application/json")
		linear := 0.0
		if mem := js.Global().Get("__wasmMemory"); !mem.IsUndefined() {
			linear = float64(mem.Get("buffer").Get("byteLength").Int()) / 1e6
		}
		json.NewEncoder(w).Encode(map[string]any{
			"linear_mb":     linear,
			"sys_mb":        float64(m.Sys) / 1e6,
			"heap_sys_mb":   float64(m.HeapSys) / 1e6,
			"heap_alloc_mb": float64(m.HeapAlloc) / 1e6,
			"heap_inuse_mb": float64(m.HeapInuse) / 1e6,
			"stack_sys_mb":  float64(m.StackSys) / 1e6,
			"num_gc":        m.NumGC,
			"num_goroutine": runtime.NumGoroutine(),
			"core_built":    s.core != nil,
			"sealed":        s.core == nil || s.core.Sealed(),
		})
	default:
		http.NotFound(w, r)
	}
}

func apiAddr() string {
	if v := strings.TrimSpace(cloudflare.Getenv(envAPIAddr)); v != "" {
		return v
	}
	return "https://openbao.worker.invalid"
}
