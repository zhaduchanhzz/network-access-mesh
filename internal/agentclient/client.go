// Package agentclient is the worker's client of the Host Agent (P3-T01; master plan §11.1, §13.6): gRPC over the
// agent's Unix socket, authenticated by the agent token (a file secret, sent as "authorization: Bearer …" on every
// call) on top of the kernel-attested peer credentials the agent checks itself (SO_PEERCRED).
//
// The client adds no validation of its own: the agent is the authority and answers every refusal with a typed
// status (RefusalOf, Retryable). Some messages carry secrets (the API key of BootstrapApiKey and
// PostRestoreReconcile, the data key of Backup and Restore — marked debug_redact in agent.proto, which protobuf-go's
// String() does NOT honour): callers never log a request or a response.
package agentclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

// DefaultSocket is the agent socket inside the worker container (host: /opt/meshguard/run/agent.sock — §11.1).
const DefaultSocket = "/run/meshguard/agent.sock"

// MaxResponseBytes caps a response from the agent.
const MaxResponseBytes = 4 << 20

// Config locates the agent.
type Config struct {
	Socket    string // absolute path of the Unix socket
	TokenFile string // absolute path of the agent token file (root:mg-sec-worker 0440 on the host — §14.2)
}

// Client is a connection to the agent. The embedded AgentServiceClient exposes every RPC; the connection is
// established lazily and re-established by gRPC after the agent restarts.
type Client struct {
	agentv1.AgentServiceClient
	conn *grpc.ClientConn
}

// MinTokenBytes is the shortest accepted agent token.
const MinTokenBytes = 32

// ReadToken reads the agent token: one line of printable ASCII, at least MinTokenBytes long. The value is never
// part of an error.
func ReadToken(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path of the agent token from the configuration
	if err != nil {
		return "", fmt.Errorf("agent token file %s: %w", path, err)
	}
	tok := strings.TrimRight(string(raw), "\r\n")
	if len(tok) < MinTokenBytes || len(tok) > 4096 {
		return "", fmt.Errorf("agent token file %s: want one line of %d..4096 bytes", path, MinTokenBytes)
	}
	for _, c := range []byte(tok) {
		if c < 0x21 || c > 0x7e {
			return "", fmt.Errorf("agent token file %s: printable ASCII without spaces only", path)
		}
	}
	return tok, nil
}

// New prepares a client; it does not connect (the first call does).
func New(cfg Config) (*Client, error) {
	if !filepath.IsAbs(cfg.Socket) {
		return nil, errors.New("agentclient: the socket must be an absolute path")
	}
	tok, err := ReadToken(cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient("unix://"+cfg.Socket,
		// local credentials: the transport is a Unix socket (security level PrivacyAndIntegrity), so the token may
		// be sent; over anything else gRPC refuses to send it.
		grpc.WithTransportCredentials(local.NewCredentials()),
		grpc.WithPerRPCCredentials(tokenCreds(tok)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxResponseBytes)),
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: 5 * time.Second, Backoff: backoff.Config{
			BaseDelay: 200 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 5 * time.Second}}),
	)
	if err != nil {
		return nil, fmt.Errorf("agentclient: %w", err)
	}
	return &Client{AgentServiceClient: agentv1.NewAgentServiceClient(conn), conn: conn}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

type tokenCreds string

func (t tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(t)}, nil
}

func (tokenCreds) RequireTransportSecurity() bool { return true }

// RefusalOf returns the typed refusal carried by an error of the agent, if any.
func RefusalOf(err error) (*agentv1.Refusal, bool) {
	st, ok := status.FromError(err)
	if !ok {
		return nil, false
	}
	for _, d := range st.Details() {
		if r, ok := d.(*agentv1.Refusal); ok {
			return r, true
		}
	}
	return nil, false
}

// Retryable reports whether a failed call may succeed later without a change of the request: the agent is
// unreachable or restarting, the per-instance lock is held (ABORTED, REFUSAL_REASON_BUSY), or the deadline passed.
// Refusals of the request itself (INVALID_ARGUMENT, FAILED_PRECONDITION, NOT_FOUND, UNAUTHENTICATED,
// PERMISSION_DENIED, RESOURCE_EXHAUSTED for an oversize message) and UNIMPLEMENTED are permanent: the job fails
// instead of retrying (§11.3).
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.Aborted, codes.DeadlineExceeded:
		return true
	}
	return false
}
