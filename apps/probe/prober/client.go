package prober

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls the prober service over its internal RPC API (Handler) — what the worker uses (MG_PROBER_URL).
type Client struct {
	base string
	hc   *http.Client
}

var _ Prober = (*Client)(nil)

// NewClient returns a client for the service at baseURL (http(s)://host:port — no path, query or user info). hc nil
// = a client with no proxy from the environment, no redirects and a 60 s timeout.
func NewClient(baseURL string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("prober: base URL must be http(s)://host[:port]")
	}
	if hc == nil {
		hc = &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Client{base: strings.TrimSuffix(u.String(), "/"), hc: hc}, nil
}

// STUN implements Prober.
func (c *Client) STUN(ctx context.Context, req STUNRequest) (STUNResult, error) {
	var out STUNResult
	err := c.call(ctx, RouteSTUN, req, &out)
	return out, err
}

// HTTPS implements Prober.
func (c *Client) HTTPS(ctx context.Context, req HTTPSRequest) (HTTPSResult, error) {
	var out HTTPSResult
	err := c.call(ctx, RouteHTTPS, req, &out)
	return out, err
}

// Edge implements Prober.
func (c *Client) Edge(ctx context.Context, req EdgeRequest) (EdgeResult, error) {
	var out EdgeResult
	err := c.call(ctx, RouteEdge, req, &out)
	return out, err
}

// Relay implements Prober.
func (c *Client) Relay(ctx context.Context, req RelayRequest) (RelayResult, error) {
	var out RelayResult
	err := c.call(ctx, RouteRelay, req, &out)
	return out, err
}

// call posts one request; a refusal of the service comes back as its *Error, any other failure as CodeRPC.
func (c *Client) call(ctx context.Context, route string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return newError(CodeInvalidRequest, "request cannot be encoded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+route, bytes.NewReader(body))
	if err != nil {
		return newError(CodeRPC, message(err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return newError(CodeRPC, message(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return newError(CodeRPC, message(err))
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error *Error `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != nil && e.Error.Code != "" {
			return e.Error
		}
		return newError(CodeRPC, fmt.Sprintf("HTTP %d from the prober", resp.StatusCode))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return newError(CodeRPC, "result cannot be decoded")
	}
	return nil
}
