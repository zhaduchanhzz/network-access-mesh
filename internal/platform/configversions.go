package platform

// The configuration versions of an instance (instance_config_versions, §6.3) as the instance detail of the Platform
// Console shows them (GET /platform/instances/{instanceId}/config-versions — P4-T03, §12.2): the rows the orchestrator
// (step 8 of §11.3) and the reconfigure job (P3-T13) write, newest first, the one tenant_instances.config_version_id
// points at marked current. rendered_config is never read (the real file lives on the host, matched by config_sha256);
// params are the non-secret render parameters as stored.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// ConfigVersion is schema InstanceConfigVersion.
type ConfigVersion struct {
	ID              uuid.UUID
	Version         int32
	Status          string
	Current         bool
	TemplateVersion string
	ConfigSHA256    string
	Params          []byte // JSON object
	CreatedAt       time.Time
	AppliedAt       *time.Time
	CreatedBy       *uuid.UUID
}

// ConfigVersionPage is one page of configuration versions.
type ConfigVersionPage struct {
	Items      []ConfigVersion
	NextCursor string
}

// ListInstanceConfigVersions is GET /platform/instances/{instanceId}/config-versions: ErrNotFound when the instance
// does not exist (checked in the same platform transaction), ErrInvalid for a limit or cursor out of range.
func (s *Service) ListInstanceConfigVersions(ctx context.Context, instanceID uuid.UUID, limit int, cursor string) (ConfigVersionPage, error) {
	if instanceID == uuid.Nil {
		return ConfigVersionPage{}, ErrNotFound
	}
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return ConfigVersionPage{}, fmt.Errorf("%w: limit must be 1–%d", ErrInvalid, MaxLimit)
	}
	p := sqlcdb.ListInstanceConfigVersionsPageParams{InstanceID: instanceID, RowLimit: int32(limit + 1)} //nolint:gosec // ≤ MaxLimit+1
	if cursor != "" {
		v, err := decodeVersionCursor(cursor)
		if err != nil {
			return ConfigVersionPage{}, err
		}
		p.BeforeVersion = &v
	}
	var out ConfigVersionPage
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if _, err := q.GetTenantInstance(ctx, instanceID); errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		rows, err := q.ListInstanceConfigVersionsPage(ctx, p)
		if err != nil {
			return err
		}
		out = ConfigVersionPage{Items: make([]ConfigVersion, 0, min(len(rows), limit))}
		for i, r := range rows {
			if i == limit {
				out.NextCursor = encodeVersionCursor(out.Items[limit-1].Version)
				break
			}
			v := ConfigVersion{ID: r.ID, Version: r.Version, Status: r.Status, Current: r.IsCurrent,
				TemplateVersion: r.TemplateVersion, ConfigSHA256: r.ConfigSha256, Params: r.Params,
				CreatedAt: r.CreatedAt.UTC(), CreatedBy: r.CreatedBy}
			if r.AppliedAt != nil {
				t := r.AppliedAt.UTC()
				v.AppliedAt = &t
			}
			out.Items = append(out.Items, v)
		}
		return nil
	})
	return out, err
}

// The cursor is opaque to clients: base64url of "v<version>" of the last item of the page (versions go down).
func encodeVersionCursor(v int32) string {
	return base64.RawURLEncoding.EncodeToString([]byte("v" + strconv.Itoa(int(v))))
}

func decodeVersionCursor(s string) (int32, error) {
	bad := fmt.Errorf("%w: invalid cursor", ErrInvalid)
	if len(s) > 64 {
		return 0, bad
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, bad
	}
	n, ok := strings.CutPrefix(string(raw), "v")
	if !ok {
		return 0, bad
	}
	v, err := strconv.ParseInt(n, 10, 32)
	if err != nil || v < 1 {
		return 0, bad
	}
	return int32(v), nil
}
