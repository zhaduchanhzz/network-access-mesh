// Package httpxtest hands the code under test listeners that the test already holds (httpx.ListenFunc), in place of
// a "free" port found by listening and closing: between that close and the bind of the code under test, another test,
// package or process — or an outgoing connection's ephemeral port — can take the port, or two lookups can return the
// same one (address already in use, or a test talking to someone else's server).
package httpxtest

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
)

// Listeners holds the loopback listeners opened by Addr until Listen hands them over. The zero value is ready; it is
// safe for concurrent use.
type Listeners struct {
	mu   sync.Mutex
	held map[string]net.Listener
}

// Addr binds 127.0.0.1:0, holds the listener and returns its address (host:port); a listener never handed over is
// closed when the test ends.
func (ls *Listeners) Addr(t testing.TB) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	ls.mu.Lock()
	if ls.held == nil {
		ls.held = map[string]net.Listener{}
	}
	ls.held[addr] = l
	ls.mu.Unlock()
	t.Cleanup(func() {
		if l := ls.take("tcp", addr); l != nil {
			_ = l.Close()
		}
	})
	return addr
}

// Listen is an httpx.ListenFunc: it hands over the listener held for address, once. Any other address is refused, so
// the code under test never binds a port of its own.
func (ls *Listeners) Listen(_ context.Context, network, address string) (net.Listener, error) {
	if l := ls.take(network, address); l != nil {
		return l, nil
	}
	return nil, fmt.Errorf("httpxtest: no listener held for %s %s (take the address from Listeners.Addr)", network, address)
}

func (ls *Listeners) take(network, address string) net.Listener {
	if network != "tcp" {
		return nil
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	l := ls.held[address]
	delete(ls.held, address)
	return l
}
