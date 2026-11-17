package idptest

import (
	"context"
	"sync"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
)

// Security records the security events a driver raises (idp.SecurityRecorder) without deduplication.
type Security struct {
	mu     sync.Mutex
	events []audit.SecurityEvent
}

// RecordSecurityEvent implements idp.SecurityRecorder.
func (s *Security) RecordSecurityEvent(_ context.Context, ev audit.SecurityEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return true, nil
}

// Events returns a copy of the recorded events.
func (s *Security) Events() []audit.SecurityEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.SecurityEvent(nil), s.events...)
}
