package runner

// Wiring of the enrollment module (P4-T06): the api serves the operations of §7.4 (requests, approval, keys, web-auth
// claim, instructions) with the SecretStore as the Vault of show-once credentials and the tag catalog's RequireTags as
// its TagGate; the worker runs enrollment.reconcile and its schedule (workerSchedules).

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/enrollment"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// credentialVault keeps a show-once enrollment credential in the SecretStore under the tenant's DEK until the
// credential expires (§13.1: an Idempotency-Key replay answers it again within its TTL, then 410), and refuses any
// reference that is not a secret of the same tenant with the enrollment name prefix.
type credentialVault struct{ s *secrets.Store }

const vaultPrefix = "enrollment-credential."

func (v credentialVault) Keep(ctx context.Context, tenantID uuid.UUID, value []byte, expires time.Time) (string, error) {
	if v.s == nil || tenantID == uuid.Nil {
		return "", errors.New("enrollment vault: no SecretStore or no tenant")
	}
	ref := secrets.TenantRef(tenantID, vaultPrefix+uuid.NewString(), 1)
	if err := v.s.Put(ctx, ref, value, secrets.WithExpiry(expires)); err != nil {
		return "", err
	}
	return ref.String(), nil
}

func (v credentialVault) Recall(ctx context.Context, tenantID uuid.UUID, ref string) ([]byte, error) {
	if v.s == nil {
		return nil, enrollment.ErrSecretGone
	}
	r, err := secrets.ParseRef(ref)
	if err != nil || r.Tenant != tenantID || len(r.Name) <= len(vaultPrefix) || r.Name[:len(vaultPrefix)] != vaultPrefix {
		return nil, errors.New("enrollment vault: not an enrollment credential of this tenant")
	}
	p, err := v.s.Get(ctx, r)
	switch {
	case errors.Is(err, secrets.ErrExpired), errors.Is(err, secrets.ErrDestroyed), errors.Is(err, secrets.ErrNotFound):
		return nil, enrollment.ErrSecretGone
	case err != nil:
		return nil, err
	}
	out := append([]byte(nil), p.Bytes()...)
	p.Wipe()
	return out, nil
}

// newEnrollment is the enrollment module of a process: the api with the Vault and the tag gate, the worker without.
func newEnrollment(d *deps, api bool) (*enrollment.Service, error) {
	cfg := enrollment.Config{Registry: d.headscale, Logger: d.log}
	if api {
		cfg.Vault = credentialVault{s: d.secrets}
		cfg.Tags = policies.RequireTags
	}
	return enrollment.New(d.st, cfg)
}
