package mailrelay

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// ListenAddr returns the address to listen on: addr unchanged without a network, otherwise addr's port on the one local
// IPv4 address inside network (the container's address on the `mail` network), so the SMTP listener is not reachable
// through the relay's other networks (mg-egress, mg-obs). No — or more than one — local address in network is an error.
func ListenAddr(addr string, network netip.Prefix, local func() ([]net.Addr, error)) (string, error) {
	if !network.IsValid() {
		return addr, nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	addrs, err := local()
	if err != nil {
		return "", err
	}
	var found []netip.Addr
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if ok && network.Contains(ip.Unmap()) {
			found = append(found, ip.Unmap())
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("expected exactly one local address in %s (the mail network), found %d", network, len(found))
	}
	return net.JoinHostPort(found[0].String(), port), nil
}

// CertFiles serves the STARTTLS certificate from a PEM pair on disk, reloaded when either file changes (a renewed
// certificate takes effect without a restart). The key never leaves the process.
type CertFiles struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	stamp             string
}

// NewCertFiles loads the pair once (a broken pair stops the start).
func NewCertFiles(certFile, keyFile string) (*CertFiles, error) {
	c := &CertFiles{certFile: certFile, keyFile: keyFile}
	if _, err := c.get(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CertFiles) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stamp := ""
	for _, f := range []string{c.certFile, c.keyFile} {
		fi, err := os.Stat(f)
		if err != nil {
			return nil, errors.New("the TLS certificate or key file cannot be read")
		}
		stamp += fmt.Sprintf("%d/%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	if c.cert != nil && stamp == c.stamp {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil // a half-written renewal: keep serving the previous pair
		}
		return nil, errors.New("the TLS certificate and key do not form a valid PEM pair")
	}
	c.cert, c.stamp = &cert, stamp
	return c.cert, nil
}

// Check is the readiness probe of the pair: loadable, and the certificate not expired.
func (c *CertFiles) Check() error {
	cert, err := c.get()
	if err != nil {
		return err
	}
	if cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
		return errors.New("the TLS certificate has expired")
	}
	return nil
}

// TLSConfig is the server configuration of STARTTLS: TLS 1.2+, the pair from disk.
func (c *CertFiles) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.get()
	}}
}
