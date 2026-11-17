package prober

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Options configures a Local prober.
type Options struct {
	// Allow is the allow-list of targets (MG_PROBE_ALLOW_TARGETS). Empty: every target is refused (fail closed).
	Allow []netip.Prefix
	// RootCAs verifies the HTTPS probes; nil = the system roots. The service sets it from MG_PROBE_CA_FILE (the
	// dev/CI CA) — a request can never change it.
	RootCAs *x509.CertPool
	// Logger receives one line per probe; build it with logx.New so values are redacted. nil = discard.
	Logger *slog.Logger
	// MaxBody bounds the body read of an HTTPS probe, in bytes; 0 = DefaultMaxBody.
	MaxBody int
	// Now is the clock of CheckedAt; nil = time.Now.
	Now func() time.Time
}

// Local runs the probes in this process.
type Local struct {
	allow   []netip.Prefix
	roots   *x509.CertPool
	log     *slog.Logger
	maxBody int
	now     func() time.Time
	ua      string
	stunRTO time.Duration
}

var _ Prober = (*Local)(nil)

// New returns a Local prober.
func New(o Options) *Local {
	l := &Local{allow: slices.Clone(o.Allow), roots: o.RootCAs, log: o.Logger, maxBody: o.MaxBody, now: o.Now,
		ua: "meshguard-probe/" + buildinfo.Version, stunRTO: 500 * time.Millisecond}
	if l.log == nil {
		l.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if l.maxBody <= 0 {
		l.maxBody = DefaultMaxBody
	}
	if l.now == nil {
		l.now = time.Now
	}
	return l
}

// timeout clamps a requested timeout (milliseconds) to (0, MaxTimeout]; 0 selects def.
func timeout(reqMS int, def time.Duration) (time.Duration, error) {
	switch {
	case reqMS == 0:
		return def, nil
	case reqMS < 0 || time.Duration(reqMS)*time.Millisecond > MaxTimeout:
		return 0, newError(CodeInvalidRequest, "timeout_ms must be 1-15000")
	}
	return time.Duration(reqMS) * time.Millisecond, nil
}

// classify maps a socket or context error to a typed failure.
func classify(ctx context.Context, err error) *Error {
	var ne net.Error
	switch {
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled):
		return newError(CodeCanceled, "the caller cancelled the probe")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return newError(CodeTimeout, "no answer before the deadline")
	case errors.Is(err, syscall.ECONNREFUSED):
		return newError(CodeRefused, "connection refused")
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return newError(CodeUnreachable, "no route to the target")
	}
	return newError(CodeNetwork, message(err))
}

// message is the redacted, bounded text of an error.
func message(err error) string {
	s := logx.RedactString(err.Error())
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func code(e *Error) string {
	if e == nil {
		return ""
	}
	return e.Code
}
