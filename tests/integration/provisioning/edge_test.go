//go:build linux && dockerintegration

package provisioning

// The test edge (PIT_ROLE=edge): the two listeners of the shared edge that the state machine and the prober use,
// with the routing rules of infrastructure/caddy/Caddyfile.tmpl — no TLS (the network of the test is private):
//
//	admin  :8081  X-MG-Token must equal the token file (else 403); X-MG-Instance ^slug$ and (/api/v1/* or GET /version)
//	              ⇒ reverse proxy to hs-<slug>:8080 with both headers removed; anything else 404; a dial error 404.
//	public :8080  Host <slug>.mesh.<base domain> and the path allow-list (/ts2021 /key /machine/ping-response /derp
//	              /derp/* /register/* /auth/* /oidc/callback) ⇒ hs-<slug>:8080; anything else 404; a dial error 404.
//
// hs-<slug> resolves through Docker's embedded DNS on the tenant network the agent attached this container to — so a
// tenant whose network is not attached (or was detached by a compensation) is unreachable, as behind the real edge.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
)

var (
	slugRE    = `[a-z][a-z0-9-]{1,30}[a-z0-9]`
	instRE    = regexp.MustCompile(`^(` + slugRE + `)$`)
	tokenRE   = regexp.MustCompile(`^[A-Za-z0-9]{40}$`)
	publicOK  = regexp.MustCompile(`^/(ts2021|key|machine/ping-response|derp|derp/.*|register/.*|auth/.*|oidc/callback)$`)
	edgeLog   = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	edgeProxy = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second, MaxIdleConnsPerHost: 4}
)

// proxyTo returns a reverse proxy to hs-<slug>:8080 that answers 404 when the instance cannot be reached.
func proxyTo(slug string, strip ...string) *httputil.ReverseProxy {
	target := &url.URL{Scheme: "http", Host: "hs-" + slug + ":8080"}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			for _, h := range strip {
				r.Out.Header.Del(h)
			}
		},
		Transport: edgeProxy,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			edgeLog.Info("upstream unreachable", "slug", slug, "error", err.Error())
			w.WriteHeader(http.StatusNotFound)
		},
	}
}

func adminHandler(tokenFile string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := agentclient.ReadToken(tokenFile)
		got := r.Header.Get("X-MG-Token")
		if err != nil || !tokenRE.MatchString(got) || subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		m := instRE.FindStringSubmatch(r.Header.Get("X-MG-Instance"))
		if m == nil || strings.Contains(r.URL.Path, `\`) ||
			(!strings.HasPrefix(r.URL.Path, "/api/v1/") && (r.Method != http.MethodGet || r.URL.Path != "/version")) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		proxyTo(m[1], "X-MG-Token", "X-MG-Instance").ServeHTTP(w, r)
	})
}

func publicHandler(baseDomain string) http.Handler {
	hostRE := regexp.MustCompile(`^(` + slugRE + `)\.mesh\.` + regexp.QuoteMeta(baseDomain) + `(:[0-9]+)?$`)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := hostRE.FindStringSubmatch(strings.ToLower(r.Host))
		if m == nil || strings.Contains(r.URL.Path, `\`) || !publicOK.MatchString(r.URL.Path) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		proxyTo(m[1], "X-MG-Token", "X-MG-Instance").ServeHTTP(w, r)
	})
}

func runEdge() int {
	tokenFile, base := os.Getenv("PIT_EDGE_TOKEN_FILE"), os.Getenv("PIT_BASE_DOMAIN")
	if _, err := agentclient.ReadToken(tokenFile); err != nil || base == "" {
		fmt.Fprintln(os.Stderr, "edge: PIT_EDGE_TOKEN_FILE (readable token) and PIT_BASE_DOMAIN are required")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	servers := []*http.Server{
		{Addr: ":8081", Handler: adminHandler(tokenFile), ReadHeaderTimeout: 10 * time.Second},
		{Addr: ":8080", Handler: publicHandler(base), ReadHeaderTimeout: 10 * time.Second},
	}
	errs := make(chan error, len(servers))
	lc := net.ListenConfig{}
	for _, s := range servers {
		l, err := lc.Listen(ctx, "tcp", s.Addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "edge:", err)
			return 1
		}
		go func() { errs <- s.Serve(l) }()
	}
	edgeLog.Info("test edge listening", "admin", ":8081", "public", ":8080", "domain", "mesh."+base)
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "edge:", err)
			return 1
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	return 0
}
