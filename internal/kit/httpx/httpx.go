// Package httpx holds the HTTP plumbing shared by MeshGuard processes: the internal listener (/healthz, /readyz,
// /metrics — never routed by the edge, §13.2, §15.1) and hardened server defaults with graceful shutdown.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Probe reports whether one dependency is ready; it must return within the context deadline.
type Probe func(ctx context.Context) error

// InternalMux serves /healthz (process alive), /readyz (every probe passes) and /metrics.
// /readyz returns only the names of failing probes, never the error text (which may contain addresses or DSNs).
func InternalMux(probes map[string]Probe, reg *prometheus.Registry, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		failing := runProbes(ctx, probes, log)
		w.Header().Set("Content-Type", "application/json")
		if len(failing) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": len(failing) == 0, "failing": failing})
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mux
}

func runProbes(ctx context.Context, probes map[string]Probe, log *slog.Logger) []string {
	var (
		mu      sync.Mutex
		failing = []string{}
		wg      sync.WaitGroup
	)
	for name, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p(ctx); err != nil {
				log.Warn("readiness probe failed", "probe", name, "error", err.Error())
				mu.Lock()
				failing = append(failing, name)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Strings(failing)
	return failing
}

// NewServer returns an http.Server with conservative timeouts and header limits.
func NewServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// ListenFunc opens a stream listener — net.ListenConfig.Listen in production; a test passes httpxtest.Listeners.Listen
// to hand over listeners it already holds (a port found "free" by listening and closing can be taken by another test or
// process before the server binds it).
type ListenFunc func(ctx context.Context, network, address string) (net.Listener, error)

// Serve runs every server until ctx is cancelled or one of them fails, then shuts all of them down gracefully.
func Serve(ctx context.Context, log *slog.Logger, servers ...*http.Server) error {
	return ServeWith(ctx, log, nil, servers...)
}

// ServeWith is Serve with the listeners opened by listen (nil: net.ListenConfig.Listen): every server's Addr is bound
// before any of them serves, a bind failure closes the listeners already opened and is returned at once.
func ServeWith(ctx context.Context, log *slog.Logger, listen ListenFunc, servers ...*http.Server) error {
	if listen == nil {
		listen = (&net.ListenConfig{}).Listen
	}
	listeners := make([]net.Listener, 0, len(servers))
	closeAll := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}
	for _, s := range servers {
		addr := s.Addr
		if addr == "" {
			addr = ":http" // as http.Server.ListenAndServe
		}
		l, err := listen(context.WithoutCancel(ctx), "tcp", addr)
		if err != nil {
			closeAll()
			log.Error("server failed", "error", err.Error())
			return err
		}
		listeners = append(listeners, l)
	}
	errc := make(chan error, len(servers))
	for i, s := range servers {
		go func() {
			log.Info("listening", "addr", listeners[i].Addr().String())
			if err := s.Serve(listeners[i]); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
		log.Error("server failed", "error", runErr.Error())
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil {
			log.Warn("shutdown", "addr", s.Addr, "error", err.Error())
		}
	}
	closeAll() // a server shut down before its Serve started has not closed its listener yet
	return runErr
}
