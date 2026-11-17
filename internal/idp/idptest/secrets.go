// Package idptest holds test doubles for the IdP module; only test code imports it.
package idptest

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// Secrets is an in-memory secrets.SecretStore with the semantics of the PostgreSQL store of internal/secrets: Put
// writes version 1 only (ErrExists afterwards), Rotate must name the latest version (ErrConflict otherwise), Destroy
// erases a version (Get then fails with ErrDestroyed). It records every reference read, and which secrets were written
// with WithPlatformOps.
type Secrets struct {
	mu        sync.Mutex
	versions  map[string]map[int32][]byte // owner/name → version → value (nil = destroyed)
	ops       map[string]bool
	Reads     []string
	FailReads bool // every Get fails (credential unavailable)
}

// NewSecrets returns an empty store.
func NewSecrets() *Secrets {
	return &Secrets{versions: map[string]map[int32][]byte{}, ops: map[string]bool{}}
}

var _ secrets.SecretStore = (*Secrets)(nil)

func key(r secrets.Ref) string { r.Version = 0; return r.String() }

// opsOf records whether a write carried an option: secrets.Option is opaque, and the IdP drivers pass exactly one,
// WithPlatformOps, for the credentials only the worker may read.
func opsOf(opts []secrets.Option) bool { return len(opts) > 0 }

// Put implements secrets.SecretStore.
func (s *Secrets) Put(_ context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if ref.Version != 1 {
		return fmt.Errorf("%w: Put creates version 1", secrets.ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(ref)
	if s.versions[k] != nil {
		return secrets.ErrExists
	}
	s.versions[k] = map[int32][]byte{1: bytes.Clone(value)}
	s.ops[k] = opsOf(opts)
	return nil
}

// Get implements secrets.SecretStore.
func (s *Secrets) Get(_ context.Context, ref secrets.Ref) (secrets.Plaintext, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Reads = append(s.Reads, ref.String())
	if s.FailReads {
		return nil, secrets.ErrNotFound
	}
	v, ok := s.versions[key(ref)][ref.Version]
	switch {
	case !ok:
		return nil, secrets.ErrNotFound
	case v == nil:
		return nil, secrets.ErrDestroyed
	}
	return secrets.Plaintext(bytes.Clone(v)), nil
}

// Rotate implements secrets.SecretStore.
func (s *Secrets) Rotate(_ context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) (secrets.Ref, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(ref)
	vs := s.versions[k]
	if vs == nil {
		return secrets.Ref{}, secrets.ErrNotFound
	}
	latest := int32(0)
	for v := range vs {
		latest = max(latest, v)
	}
	if latest != ref.Version {
		return secrets.Ref{}, secrets.ErrConflict
	}
	next := ref
	next.Version++
	vs[next.Version] = bytes.Clone(value)
	return next, nil
}

// Destroy implements secrets.SecretStore.
func (s *Secrets) Destroy(_ context.Context, ref secrets.Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	vs := s.versions[key(ref)]
	if _, ok := vs[ref.Version]; !ok {
		return secrets.ErrNotFound
	}
	vs[ref.Version] = nil
	return nil
}

// Value returns a stored value (test assertions), "" when absent or destroyed.
func (s *Secrets) Value(ref secrets.Ref) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.versions[key(ref)][ref.Version])
}

// Latest returns the latest version number of ref's secret (0 when absent).
func (s *Secrets) Latest(ref secrets.Ref) int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	latest := int32(0)
	for v := range s.versions[key(ref)] {
		latest = max(latest, v)
	}
	return latest
}

// WrittenWithOptions reports whether the secret was first written with an option (WithPlatformOps in practice).
func (s *Secrets) WrittenWithOptions(ref secrets.Ref) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ops[key(ref)]
}

// Destroyed reports whether a version exists and was destroyed.
func (s *Secrets) Destroyed(ref secrets.Ref) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[key(ref)][ref.Version]
	return ok && v == nil
}
