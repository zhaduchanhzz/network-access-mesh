package platform

// System settings (P4-T03a; §6.3 system_settings, §8.5 platform.settings:read / :update): the closed set of keys of
// internal/config (config.SystemSettings) — writable configuration keys with their validator, the read-only maintenance
// flag (host commands only — P3-T17), never the internal read cursors of idp.audit_sync (P3-T15).

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// ActionSettingUpdate is the audit action of PUT /platform/settings/{key}.
const ActionSettingUpdate = "platform.settings.update"

// Setting is schema SystemSetting.
type Setting struct {
	Key         string
	Value       []byte // JSON as stored; nil when the row is absent
	Default     []byte // JSON; nil when the reader has no default
	Writable    bool
	Description string
	Version     int64 // 0 when the row is absent
	UpdatedAt   *time.Time
	UpdatedBy   *uuid.UUID
	ETag        string // versionETag(Version): "0" when absent
}

func settingView(spec config.SystemSetting, row *sqlcdb.SystemSetting) Setting {
	s := Setting{Key: spec.Key, Writable: spec.Writable, Description: spec.Description, Default: spec.Default,
		ETag: versionETag(0)}
	if row != nil {
		at := row.UpdatedAt.UTC()
		s.Value, s.Version, s.UpdatedAt, s.UpdatedBy, s.ETag = row.Value, row.Version, &at, row.UpdatedBy, versionETag(row.Version)
	}
	return s
}

// ListSettings is GET /platform/settings: every served key, sorted.
func (s *Service) ListSettings(ctx context.Context) ([]Setting, error) {
	specs := config.SystemSettings()
	keys := make([]string, 0, len(specs))
	for _, sp := range specs {
		keys = append(keys, sp.Key)
	}
	var out []Setting
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListServedSystemSettings(ctx, keys)
		if err != nil {
			return err
		}
		byKey := map[string]*sqlcdb.SystemSetting{}
		for i := range rows {
			byKey[rows[i].Key] = &rows[i]
		}
		out = make([]Setting, 0, len(specs))
		for _, sp := range specs {
			out = append(out, settingView(sp, byKey[sp.Key]))
		}
		return nil
	})
	return out, err
}

// GetSetting is GET /platform/settings/{key}: an unknown key — or an internal cursor — is 404.
func (s *Service) GetSetting(ctx context.Context, key string) (Setting, error) {
	spec, ok := config.LookupSystemSetting(key)
	if !ok {
		return Setting{}, ErrNotFound
	}
	var out Setting
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetSystemSetting(ctx, key)
		switch {
		case errors.Is(err, store.ErrNoRows):
			out = settingView(spec, nil)
		case err != nil:
			return err
		default:
			out = settingView(spec, &row)
		}
		return nil
	})
	return out, err
}

// PutSetting is PUT /platform/settings/{key} (Super Admin): a writable key, a value its validator accepts (422), the
// caller's step-up, If-Match (the ETag of GET — "0" for a key without a row); the row is locked, written and audited
// (before/after) in one transaction. A read-only key ⇒ 422 read_only.
func (s *Service) PutSetting(ctx context.Context, a Actor, key string, value []byte, ifMatch string) (Setting, error) {
	spec, ok := config.LookupSystemSetting(key)
	if !ok {
		return Setting{}, ErrNotFound
	}
	if !spec.Writable {
		return Setting{}, invalid("key", ReasonReadOnly)
	}
	canon, err := spec.CheckValue(value)
	if err != nil {
		return Setting{}, invalid("value", ReasonInvalid)
	}
	if err := stepUp(a, time.Now()); err != nil {
		return Setting{}, err
	}
	var out Setting
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		now := time.Now().UTC()
		by := a.IdentityID
		cur, err := q.LockSystemSetting(ctx, key)
		var before any
		var row sqlcdb.SystemSetting
		switch {
		case errors.Is(err, store.ErrNoRows):
			if err := ifMatchVersion(ifMatch, 0); err != nil {
				return err
			}
			row, err = q.InsertSystemSettingIfAbsent(ctx, sqlcdb.InsertSystemSettingIfAbsentParams{Key: key, Value: canon,
				UpdatedBy: &by, Now: now})
			if errors.Is(err, store.ErrNoRows) { // created concurrently after the lock attempt: the caller's ETag is stale
				return refuse(ErrPreconditionFailed, "if_match_stale")
			}
			if err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if err := ifMatchVersion(ifMatch, cur.Version); err != nil {
				return err
			}
			before = string(cur.Value)
			if row, err = q.UpdateSystemSettingValue(ctx, sqlcdb.UpdateSystemSettingValueParams{Value: canon,
				UpdatedBy: &by, Now: now, Key: key}); err != nil {
				return err
			}
		}
		out = settingView(spec, &row)
		return audit.Record(ctx, q, audit.Event{Action: ActionSettingUpdate, ResourceType: "setting", ResourceID: key,
			Details: audit.Details{"key": key, "before": before, "after": string(row.Value), "version": row.Version}})
	})
	return out, err
}
