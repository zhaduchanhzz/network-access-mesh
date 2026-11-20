package platform

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TenantLabel is how the Platform Console names a tenant next to an object of it (G4b-E12: slug and name instead of a
// UUID; the plan key of its live subscription — "" without one).
type TenantLabel struct {
	Slug string
	Name string
	Plan string
}

// Labels names the tenants and hosts referenced by one page of the Platform Console (an instance, job, relay region or
// identity provider list, the tenant list) — one batched read per kind on the platform pool. An id without a row (a
// tenant or host the registry does not know) is simply absent from the maps.
type Labels struct {
	Tenants map[uuid.UUID]TenantLabel
	Hosts   map[uuid.UUID]string
}

// Tenant returns the label of a tenant, ok=false when unknown or id is nil.
func (l Labels) Tenant(id *uuid.UUID) (TenantLabel, bool) {
	if id == nil {
		return TenantLabel{}, false
	}
	t, ok := l.Tenants[*id]
	return t, ok
}

// maxLabelIDs bounds one lookup (a page holds at most MaxLimit objects, each naming one tenant and one host).
const maxLabelIDs = 2 * MaxLimit

// Labels reads the labels of tenantIDs and hostIDs (duplicates and nil ids ignored).
func (s *Service) Labels(ctx context.Context, tenantIDs, hostIDs []uuid.UUID) (Labels, error) {
	tids, hids := distinct(tenantIDs), distinct(hostIDs)
	out := Labels{Tenants: make(map[uuid.UUID]TenantLabel, len(tids)), Hosts: make(map[uuid.UUID]string, len(hids))}
	if len(tids) == 0 && len(hids) == 0 {
		return out, nil
	}
	if len(tids) > maxLabelIDs || len(hids) > maxLabelIDs {
		return Labels{}, fmt.Errorf("%w: too many ids for one label lookup", ErrInvalid)
	}
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if len(tids) > 0 {
			rows, err := q.ListTenantLabels(ctx, tids)
			if err != nil {
				return err
			}
			for _, r := range rows {
				out.Tenants[r.ID] = TenantLabel{Slug: r.Slug, Name: r.Name, Plan: r.PlanKey}
			}
		}
		if len(hids) > 0 {
			rows, err := q.ListHostNames(ctx, hids)
			if err != nil {
				return err
			}
			for _, r := range rows {
				out.Hosts[r.ID] = r.Name
			}
		}
		return nil
	})
	if err != nil {
		return Labels{}, fmt.Errorf("platform: labels: %w", err)
	}
	return out, nil
}

func distinct(ids []uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if id != uuid.Nil && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}
