package main

// `meshguard-worker mailrelay` — the SMTP bridge of the outbound e-mail relay (P3-T05b-mail, internal/mailrelay): its
// own container from the worker image (service `mail-bridge` of mg-app — tools/render_app.py), SMTP host `mailrelay` on the internal
// network `mail` (mailrelay:587, STARTTLS with the internal CA of infrastructure/host/mail-secrets.sh), forwarding each
// message to the Cloudflare Worker (MG_MAILRELAY_URL) signed with the HMAC key file. Internal listener (MG_INTERNAL_ADDR):
// /healthz, /readyz (smtp_listener, hmac_key, tls_certificate), /metrics (meshguard_mailrelay_*). Configuration:
// internal/config.LoadMailRelay. Exit status: 0 stopped, 1 failed, 2 usage or configuration error.

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/mailrelay"
)

// listenTCP opens the listeners of the relay (SMTP, internal); the tests hand over listeners they already hold
// (httpxtest.Listeners).
var listenTCP httpx.ListenFunc = (&net.ListenConfig{}).Listen

const mailRelayUsage = "usage: meshguard-worker mailrelay   (SMTP bridge to the Cloudflare Worker — MG_MAILRELAY_*)\n"

// mailRelay runs the relay until ctx ends. interfaces lists the local addresses (net.InterfaceAddrs; tests).
func mailRelay(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, environ []string,
	interfaces func() ([]net.Addr, error),
) int {
	if len(args) != 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker mailrelay: no argument expected\n"+mailRelayUsage)
		return 2
	}
	cfg, err := config.LoadMailRelay(getenv, environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker mailrelay: invalid configuration:\n%v\n", err)
		return 2
	}
	log := logx.New(stdout, cfg.LogLevel, "mailrelay")
	log.Info("starting", "version", buildinfo.Version, "commit", buildinfo.Commit, "env", cfg.Env)
	fail := func(what string, err error) int {
		log.Error("mail relay cannot start", "step", what, "error", logx.RedactString(err.Error()))
		return 1
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "meshguard_build_info", Help: "Build information of the running MeshGuard process.",
			ConstLabels: prometheus.Labels{"service": "mailrelay", "version": buildinfo.Version, "commit": buildinfo.Commit}},
			func() float64 { return 1 }))
	metrics, err := mailrelay.NewMetrics(reg)
	if err != nil {
		return fail("metrics", err)
	}
	var roots *x509.CertPool
	if cfg.CAFile != "" {
		if roots, err = x509.SystemCertPool(); err != nil {
			roots = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // G304: deployment configuration (MG_MAILRELAY_CA_FILE)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return fail("ca", errors.New("MG_MAILRELAY_CA_FILE: no PEM certificate could be read"))
		}
	}
	fwd, err := mailrelay.NewHTTPForwarder(mailrelay.ForwarderConfig{URL: cfg.URL, KeyFile: cfg.HMACKeyFile, RootCAs: roots,
		Metrics: metrics, UserAgent: "meshguard-mailrelay/" + buildinfo.Version})
	if err != nil {
		return fail("forwarder", err)
	}
	if err := mailrelay.KeyReadable(cfg.HMACKeyFile); err != nil {
		return fail("hmac_key", err)
	}
	probes := map[string]httpx.Probe{"hmac_key": func(context.Context) error { return mailrelay.KeyReadable(cfg.HMACKeyFile) }}
	scfg := mailrelay.Config{Hostname: cfg.Hostname, AllowedFrom: cfg.AllowedFrom, Forwarder: fwd, Timeout: cfg.Timeout,
		Rate: cfg.Rate, Logger: log, Metrics: metrics}
	if cfg.TLSCertFile != "" {
		certs, err := mailrelay.NewCertFiles(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return fail("tls", err)
		}
		scfg.TLS = certs.TLSConfig()
		probes["tls_certificate"] = func(context.Context) error { return certs.Check() }
	} else {
		log.Warn("mail relay without TLS: plain-text SMTP — allowed on the dev/CI stack only")
	}
	srv, err := mailrelay.NewServer(scfg)
	if err != nil {
		return fail("server", err)
	}
	probes["smtp_listener"] = func(context.Context) error {
		if !srv.Ready() {
			return errors.New("the SMTP listener is not accepting connections")
		}
		return nil
	}
	addr, err := mailrelay.ListenAddr(cfg.SMTPAddr, cfg.SMTPNetwork, interfaces)
	if err != nil {
		return fail("listen", err)
	}
	ln, err := listenTCP(ctx, "tcp", addr)
	if err != nil {
		return fail("listen", err)
	}
	host := ""
	if u, err := url.Parse(cfg.URL); err == nil {
		host = u.Hostname()
	}
	log.Info("mail relay ready", "smtp", ln.Addr().String(), "starttls", scfg.TLS != nil, "worker_host", host,
		"senders", len(cfg.AllowedFrom), "rate_per_minute", cfg.Rate, "timeout", cfg.Timeout.String())
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	smtpErr := make(chan error, 1)
	go func() {
		err := srv.Serve(runCtx, ln)
		cancel() // the SMTP side stopped: stop the internal listener too
		smtpErr <- err
	}()
	httpErr := httpx.ServeWith(runCtx, log, listenTCP, httpx.NewServer(cfg.InternalAddr, httpx.InternalMux(probes, reg, log), log))
	cancel()
	if err := <-smtpErr; err != nil {
		log.Error("SMTP listener failed", "error", err.Error())
		return 1
	}
	if httpErr != nil {
		return 1
	}
	log.Info("stopped")
	return 0
}
