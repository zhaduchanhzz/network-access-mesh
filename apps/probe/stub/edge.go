package stub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Edge stands in for the edge's public listener (§14.6) in front of tenant control planes:
//
//   - TLS with strict SNI: only names under the mesh domain have a certificate (one wildcard, signed by a CA made at
//     start); any other SNI gets a handshake failure (no default certificate). With Lenient, every SNI gets the
//     wildcard certificate instead (to test name verification on the client side).
//   - Host must equal the SNI (Caddy's strict_sni_host), else 421.
//   - A host that is not <tenant>.<mesh> of a known tenant ⇒ 404 (the edge's uniform answer).
//   - Allow-list: GET /key?v=N with N ≥ 113 ⇒ 200 {"publicKey": "mkey:…"} (the tenant's own key; without v ⇒ 400);
//     /derp/probe ⇒ 200 (empty); /derp, /derp/*, /ts2021, /machine/ping-response, /register/*, /auth/*,
//     /oidc/callback ⇒ 200 "ok"; every other path ⇒ 404. Leak makes listed paths answer 200 (a broken allow-list).
type Edge struct {
	// CA verifies the edge's certificate (the only root a client should trust for it).
	CA *x509.CertPool
	// PublicKeys maps tenant host → its Noise public key ("mkey:<64 hex>").
	PublicKeys map[string]string

	caDER   []byte
	mesh    string
	srv     *http.Server
	ln      net.Listener
	wg      sync.WaitGroup
	mu      sync.Mutex
	leak    map[string]bool
	lenient bool
	reqs    []Request
	conns   int
}

// Request is one request the edge answered: the raw request target and Host, as received.
type Request struct {
	SNI, Host, Target string
}

// NewEdge listens on addr (e.g. "127.0.0.1:0") for the tenants (slugs) under mesh (e.g. "mesh.example.test").
func NewEdge(addr, mesh string, tenants ...string) (*Edge, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "MeshGuard prober stub CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "*." + mesh},
		DNSNames: []string{"*." + mesh}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	e := &Edge{CA: x509.NewCertPool(), PublicKeys: map[string]string{}, caDER: caDER, mesh: strings.ToLower(mesh),
		leak: map[string]bool{}}
	e.CA.AddCert(caCert)
	for _, t := range tenants {
		sum := sha256.Sum256([]byte("stub noise key " + t + "." + mesh))
		e.PublicKeys[t+"."+e.mesh] = "mkey:" + hex.EncodeToString(sum[:])
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	e.ln = ln
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			e.mu.Lock()
			lenient := e.lenient
			e.mu.Unlock()
			if lenient || strings.HasSuffix(strings.ToLower(h.ServerName), "."+e.mesh) {
				return cert, nil
			}
			return nil, errors.New("no certificate for this server name")
		}}
	e.srv = &http.Server{Handler: http.HandlerFunc(e.serve), ReadHeaderTimeout: 5 * time.Second, TLSConfig: tlsCfg,
		ErrorLog: log.New(io.Discard, "", 0), // refused handshakes are the point of several tests
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				e.mu.Lock()
				e.conns++
				e.mu.Unlock()
			}
		}}
	e.wg.Go(func() { _ = e.srv.ServeTLS(ln, "", "") })
	return e, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n
}

// Addr is the address the edge listens on.
func (e *Edge) Addr() netip.AddrPort { return e.ln.Addr().(*net.TCPAddr).AddrPort() }

// CAPEM is the CA certificate in PEM (for a CA file — MG_PROBE_CA_FILE).
func (e *Edge) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.caDER})
}

// Host returns the control hostname of a tenant slug.
func (e *Edge) Host(slug string) string { return slug + "." + e.mesh }

// Leak makes the listed paths answer 200 instead of 404 (a broken allow-list).
func (e *Edge) Leak(paths ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range paths {
		e.leak[p] = true
	}
}

// SetLenient serves the wildcard certificate for any SNI (default: strict SNI).
func (e *Edge) SetLenient(v bool) { e.mu.Lock(); e.lenient = v; e.mu.Unlock() }

// Requests lists the requests answered so far.
func (e *Edge) Requests() []Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Request(nil), e.reqs...)
}

// Conns counts the TCP connections accepted so far.
func (e *Edge) Conns() int { e.mu.Lock(); defer e.mu.Unlock(); return e.conns }

// Close stops the edge.
func (e *Edge) Close() error {
	err := e.srv.Close()
	e.wg.Wait()
	return err
}

var allowExact = map[string]bool{"/derp": true, "/ts2021": true, "/machine/ping-response": true, "/oidc/callback": true}

func (e *Edge) serve(w http.ResponseWriter, r *http.Request) {
	sni := ""
	if r.TLS != nil {
		sni = strings.ToLower(r.TLS.ServerName)
	}
	host := strings.ToLower(r.Host)
	e.mu.Lock()
	e.reqs = append(e.reqs, Request{SNI: sni, Host: r.Host, Target: r.RequestURI})
	leak := e.leak[r.URL.EscapedPath()]
	e.mu.Unlock()
	if host != sni {
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	key, known := e.PublicKeys[host]
	path := r.URL.EscapedPath()
	switch {
	case !known:
		http.NotFound(w, r)
	case leak:
		_, _ = fmt.Fprintln(w, "leaked")
	case path == "/key":
		v, err := strconv.Atoi(r.URL.Query().Get("v"))
		if err != nil || v < 113 {
			http.Error(w, "missing or unsupported capability version", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"legacyPublicKey": key, "publicKey": key})
	case path == "/derp/probe":
		w.WriteHeader(http.StatusOK)
	case allowExact[path], strings.HasPrefix(path, "/derp/"), strings.HasPrefix(path, "/register/"),
		strings.HasPrefix(path, "/auth/"):
		_, _ = fmt.Fprintln(w, "ok")
	default:
		http.NotFound(w, r)
	}
}
