package secrets

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Latest returns the reference of the latest version of the secret name of tenant (uuid.Nil = a platform secret),
// destroyed or not — the version Rotate expects. It reads no ciphertext. ErrNotFound when the secret has no version
// visible to the pool (RLS hides other tenants and, from the api roles, platform_ops). Used by the admin commands of
// P2-T11 to store a credential idempotently: Put version 1 the first time, Rotate from the latest afterwards — also
// after an earlier run that stored a version but died before recording it.
func (s *Store) Latest(ctx context.Context, tenant uuid.UUID, name string) (Ref, error) {
	probe := Ref{Tenant: tenant, Name: name, Version: 1}
	if err := probe.Validate(); err != nil {
		return Ref{}, fmt.Errorf("secrets: latest: %w", err)
	}
	var out Ref
	err := s.tx(ctx, tenant, func(q *sqlcdb.Queries) error {
		row, err := s.latestRow(ctx, q, probe)
		if err != nil {
			return err
		}
		if _, err := rowOwner(row, probe); err != nil {
			return err
		}
		out = Ref{Tenant: tenant, Name: name, Version: row.Version}
		return nil
	})
	s.reportIntegrity(ctx, "latest", probe, err)
	if err != nil {
		return Ref{}, fmt.Errorf("secrets: latest %s: %w", probe.ownerSegment()+"/"+name, err)
	}
	return out, nil
}
