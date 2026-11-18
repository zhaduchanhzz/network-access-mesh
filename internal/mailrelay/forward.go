package mailrelay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

// Class is what the SMTP client is told about one message.
type Class int

// Outcome classes: Delivered and Partial answer 250 (at least one recipient was sent — a retry would duplicate it),
// Temporary answers 451 (the client retries later), Permanent answers 554.
const (
	Delivered Class = iota
	Partial
	Temporary
	Permanent
)

func (c Class) String() string {
	switch c {
	case Delivered:
		return "delivered"
	case Partial:
		return "partial"
	case Temporary:
		return "temporary"
	default:
		return "permanent"
	}
}

// Outcome of handing one message to the Worker.
type Outcome struct {
	Class    Class
	Code     string // stable code: the Worker's (sent, partial, send_failed, auth_signature…) or local (timeout, network…)
	Status   int    // HTTP status of the last attempt; 0 = no answer
	Attempts int
	Sent     int // recipients the Worker reported sent
	Failed   int // recipients the Worker reported failed
}

// Forwarder hands one message (envelope + raw RFC 5322 bytes) to the Worker.
type Forwarder interface {
	Forward(ctx context.Context, from string, to []string, raw []byte) Outcome
}

// Header names of the signed request (infrastructure/mail/cf-worker).
const (
	HeaderTimestamp = "X-MG-Timestamp"
	HeaderSignature = "X-MG-Signature"
	minKeyBytes     = 32
	maxKeyBytes     = 4096
	maxAnswerBytes  = 64 << 10
)

// ForwarderConfig configures NewHTTPForwarder.
type ForwarderConfig struct {
	URL            string         // https://…/v1/send
	KeyFile        string         // HMAC key (file secret), read at every attempt
	RootCAs        *x509.CertPool // nil = system roots
	Attempts       int            // default 3
	AttemptTimeout time.Duration  // default 5 s
	Backoff        []time.Duration
	UserAgent      string
	Metrics        *Metrics
	Now            func() time.Time // tests
}

// HTTPForwarder posts signed requests to the Worker with bounded retries.
type HTTPForwarder struct {
	cfg    ForwarderConfig
	client *http.Client
}

// NewHTTPForwarder returns the forwarder. Redirects are never followed (the signed body would go elsewhere).
func NewHTTPForwarder(cfg ForwarderConfig) (*HTTPForwarder, error) {
	if cfg.URL == "" || cfg.KeyFile == "" {
		return nil, errors.New("mailrelay: the Worker URL and the HMAC key file are required")
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 3
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = 5 * time.Second
	}
	if cfg.Backoff == nil {
		cfg.Backoff = []time.Duration{250 * time.Millisecond, time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "meshguard-mailrelay"
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: cfg.AttemptTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &HTTPForwarder{cfg: cfg, client: client}, nil
}

type sendRequest struct {
	From   string   `json:"from"`
	To     []string `json:"to"`
	RawB64 string   `json:"raw_b64"`
}

type sendAnswer struct {
	Code   string `json:"code"`
	Sent   int    `json:"sent"`
	Failed int    `json:"failed"`
}

var codeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// Forward posts the message, retrying a network error, a timeout, 429 and 5xx while attempts and the context allow.
func (f *HTTPForwarder) Forward(ctx context.Context, from string, to []string, raw []byte) Outcome {
	body, err := json.Marshal(sendRequest{From: from, To: to, RawB64: base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		return Outcome{Class: Permanent, Code: "encode"}
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	var out Outcome
	for attempt := 1; ; attempt++ {
		var retry bool
		out, retry = f.once(ctx, body, digest)
		out.Attempts = attempt
		if !retry || attempt >= f.cfg.Attempts {
			return out
		}
		wait := f.cfg.Backoff[min(attempt-1, len(f.cfg.Backoff)-1)]
		if d, ok := ctx.Deadline(); ok && time.Until(d) < wait+500*time.Millisecond {
			return out // no time left for a useful attempt
		}
		select {
		case <-ctx.Done():
			return out
		case <-time.After(wait):
		}
	}
}

// once makes one signed request. retry reports whether another attempt may succeed.
func (f *HTTPForwarder) once(ctx context.Context, body []byte, digest string) (Outcome, bool) {
	key, err := readKey(f.cfg.KeyFile)
	if err != nil {
		return Outcome{Class: Temporary, Code: "key_unavailable"}, false
	}
	ts := strconv.FormatInt(f.cfg.Now().Unix(), 10)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(ts + "\n" + digest))
	sig := hex.EncodeToString(mac.Sum(nil))
	clear(key)
	actx, cancel := context.WithTimeout(ctx, f.cfg.AttemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodPost, f.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return Outcome{Class: Temporary, Code: "request"}, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", f.cfg.UserAgent)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, sig)
	resp, err := f.client.Do(req)
	if err != nil {
		f.cfg.Metrics.attempt(0)
		code := "network"
		if errors.Is(err, context.DeadlineExceeded) || actx.Err() != nil {
			code = "timeout"
		}
		return Outcome{Class: Temporary, Code: code}, ctx.Err() == nil
	}
	defer func() { _ = resp.Body.Close() }()
	f.cfg.Metrics.attempt(resp.StatusCode)
	var ans sendAnswer
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if json.Unmarshal(data, &ans) != nil || !codeRE.MatchString(ans.Code) {
		ans = sendAnswer{Code: fmt.Sprintf("http_%d", resp.StatusCode)}
	}
	out := Outcome{Code: ans.Code, Status: resp.StatusCode, Sent: max(ans.Sent, 0), Failed: max(ans.Failed, 0)}
	switch st := resp.StatusCode; {
	case st == http.StatusOK:
		out.Class = Delivered
		if ans.Code == "partial" || (out.Sent > 0 && out.Failed > 0) {
			out.Class = Partial
		}
		return out, false
	case st == http.StatusTooManyRequests || st == http.StatusRequestTimeout || st >= 500:
		out.Class = Temporary
		return out, true
	case st == http.StatusUnauthorized || st == http.StatusNotFound || st < 400:
		// wrong key, clock, URL or a redirect: a fault of the deployment, not of the message — the client keeps it and
		// retries later, the operator fixes the relay (meshguard_mailrelay_forward_attempts_total{status="4xx"})
		out.Class = Temporary
		return out, false
	default:
		out.Class = Permanent
		return out, false
	}
}

// readKey reads the HMAC key file (one value, trailing newline removed). The caller clears the bytes.
func readKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: deployment configuration (MG_MAILRELAY_HMAC_KEY_FILE)
	if err != nil {
		return nil, errors.New("the HMAC key file cannot be read")
	}
	k := bytes.TrimRight(b, "\r\n")
	if len(k) < minKeyBytes || len(k) > maxKeyBytes {
		clear(b)
		return nil, fmt.Errorf("the HMAC key must hold %d to %d bytes", minKeyBytes, maxKeyBytes)
	}
	return k, nil
}

// KeyReadable is the readiness probe of the HMAC key file (never its value).
func KeyReadable(path string) error {
	k, err := readKey(path)
	clear(k)
	return err
}
