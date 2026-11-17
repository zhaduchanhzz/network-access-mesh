package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Peer authentication (§11.1, §14.4) — both checks are required on every call:
//
//  1. SO_PEERCRED at connection time (peerCreds): the kernel-attested UID (and optionally GID) of the connecting
//     process must be in MG_AGENT_PEER_UIDS (the worker, 65532). It cannot be forged, but it cannot tell the
//     worker from the api either (both run distroless nonroot 65532) — the socket directory is mounted into the
//     worker only, which is a deployment property, not something the agent can verify.
//  2. The agent token (authorize): a file secret of the worker's group (mg-sec-worker 0440) presented as
//     "authorization: Bearer <token>" on every call and compared in constant time. It separates the worker from
//     any other process with the same UID, and is what survives a later move to mTLS over TCP (multi-host).
//
// The agent's own UID (the container healthcheck runs `meshguard-agent healthcheck` inside the agent container) is
// accepted for Health only, and still needs the token.

// healthMethod is the only method open to the agent's own UID.
const healthMethod = "/meshguard.agent.v1.AgentService/Health"

// peerInfo is the AuthInfo of an accepted connection.
type peerInfo struct {
	credentials.CommonAuthInfo
	UID, GID uint32
	PID      int32
	// Self: the peer runs as the agent's own UID and is not an allowed worker UID (Health only).
	Self bool
}

func (peerInfo) AuthType() string { return "peercred" }

var errPeerRefused = errors.New("peer credentials not allowed")

// peerCreds is the server-side transport credentials: no handshake bytes, only the SO_PEERCRED check.
type peerCreds struct {
	uids, gids []uint32
	self       uint32
	log        *slog.Logger
}

func (p *peerCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uid, gid, pid, err := peerCred(conn)
	if err != nil {
		p.log.Warn("agent_peer_refused", "reason", "peer credentials unavailable", "error", err)
		return nil, nil, errPeerRefused
	}
	allowed := slices.Contains(p.uids, uid) && (len(p.gids) == 0 || slices.Contains(p.gids, gid))
	self := !allowed && uid == p.self
	if !allowed && !self {
		// audit line of a refused connection: who tried (kernel-attested), nothing else is known yet
		p.log.Warn("agent_peer_refused", "reason", "uid/gid not in MG_AGENT_PEER_UIDS/MG_AGENT_PEER_GIDS",
			"peer_uid", uid, "peer_gid", gid, "peer_pid", pid)
		return nil, nil, errPeerRefused
	}
	return conn, peerInfo{CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		UID: uid, GID: gid, PID: pid, Self: self}, nil
}

func (p *peerCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("peerCreds is server-side only")
}

func (p *peerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

func (p *peerCreds) Clone() credentials.TransportCredentials {
	c := *p
	return &c
}

func (p *peerCreds) OverrideServerName(string) error { return nil }

// authorize runs first on every call: the token, then the Health-only rule of the agent's own UID.
func (s *server) authorize(ctx context.Context, method string) (peerInfo, error) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return peerInfo{}, unauthenticated("no peer")
	}
	info, ok := pr.AuthInfo.(peerInfo)
	if !ok {
		return peerInfo{}, unauthenticated("connection not authenticated by peer credentials")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("authorization")
	if len(vals) != 1 {
		return info, unauthenticated("exactly one authorization header is required")
	}
	tok, ok := strings.CutPrefix(vals[0], "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(tok), s.token) != 1 {
		return info, unauthenticated("wrong agent token")
	}
	if info.Self && method != healthMethod {
		return info, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_PERMISSION_DENIED,
			Msg: "the agent's own UID may call Health only"}
	}
	return info, nil
}

func unauthenticated(msg string) error {
	return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_UNAUTHENTICATED, Msg: msg}
}
