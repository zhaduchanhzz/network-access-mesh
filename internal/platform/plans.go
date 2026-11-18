package platform

// Subscription plans (P4-T03a; §6.3 subscription_plans, §13.3 PlanLimits, §8.5 platform.plan:read / :manage). The key
// is immutable (TenantCreate.plan_key); limits follow PlanLimits — every plan holds the four quota keys (CHECK
// mg_plan_limits_valid(limits, false) of 0012, mirrored by CheckPlanLimits so a 422 names the field); a closed plan
// takes no new tenant, the tenants on it keep it. A new limit applies at the next quota check.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Audit actions and the operation of the plan writes.
const (
	ActionPlanCreate    = "platform.plan.create"
	ActionPlanUpdate    = "platform.plan.update"
	CreatePlanOperation = "createPlatformPlan"
)

// QuotaKeys are the four quota keys every plan holds (§6.3, §13.3).
var QuotaKeys = []string{"max_devices", "max_users", "max_tagged_devices", "max_live_enrollment_credentials"}

// Plan is schema Plan.
type Plan struct {
	ID          uuid.UUID
	Key         string
	Name        string
	Limits      json.RawMessage
	IsActive    bool
	TenantCount int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Version     int64
	ETag        string
}

func planView(p sqlcdb.SubscriptionPlan, count int64) Plan {
	return Plan{ID: p.ID, Key: p.Key, Name: p.Name, Limits: json.RawMessage(p.Limits), IsActive: p.IsActive,
		TenantCount: count, CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(), Version: p.Version,
		ETag: versionETag(p.Version)}
}

var planKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// CheckPlanLimits mirrors mg_plan_limits_valid (0012): an object of PlanLimits keys only; max_* integers 0…2³¹−1,
// backup_interval_minutes 1…2³¹−1, instance {cpus 0 < n ≤ 1024, memory_mb, pids integers 1…2³¹−1}; partial = false ⇒
// the four quota keys are required. It returns the field of the first problem ("" when valid).
func CheckPlanLimits(raw []byte, partial bool) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return "limits"
	}
	integer := func(v any, lo int64) bool {
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		i, err := n.Int64()
		return err == nil && i >= lo && i <= 2147483647
	}
	if !partial {
		for _, k := range QuotaKeys {
			if _, ok := m[k]; !ok {
				return "limits." + k
			}
		}
	}
	for k, v := range m {
		switch k {
		case "max_devices", "max_users", "max_tagged_devices", "max_live_enrollment_credentials":
			if !integer(v, 0) {
				return "limits." + k
			}
		case "backup_interval_minutes":
			if !integer(v, 1) {
				return "limits." + k
			}
		case "instance":
			o, ok := v.(map[string]any)
			if !ok {
				return "limits.instance"
			}
			for ik, iv := range o {
				switch ik {
				case "cpus":
					n, ok := iv.(json.Number)
					f, err := n.Float64()
					if !ok || err != nil || f <= 0 || f > 1024 {
						return "limits.instance.cpus"
					}
				case "memory_mb", "pids":
					if !integer(iv, 1) {
						return "limits.instance." + ik
					}
				default:
					return "limits.instance." + ik
				}
			}
		default:
			return "limits." + k
		}
	}
	return ""
}

func validPlanName(s string) bool {
	return utf8.ValidString(s) && strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= 200
}

// ListPlans is GET /platform/plans.
func (s *Service) ListPlans(ctx context.Context) ([]Plan, error) {
	var out []Plan
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListPlansWithUsage(ctx)
		if err != nil {
			return err
		}
		out = make([]Plan, 0, len(rows))
		for _, r := range rows {
			out = append(out, planView(r.SubscriptionPlan, r.TenantCount))
		}
		return nil
	})
	return out, err
}

// GetPlan is GET /platform/plans/{id}.
func (s *Service) GetPlan(ctx context.Context, id uuid.UUID) (Plan, error) {
	var out Plan
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetPlanWithUsage(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = planView(r.SubscriptionPlan, r.TenantCount)
		return nil
	})
	return out, err
}

// PlanCreate is POST /platform/plans.
type PlanCreate struct {
	Key      string
	Name     string
	Limits   []byte
	IsActive bool
}

// CreatePlan is POST /platform/plans (Idempotency-Key: a replay returns the stored plan).
func (s *Service) CreatePlan(ctx context.Context, a Actor, in PlanCreate, idem *Idempotency) (Plan, error) {
	switch {
	case !planKeyRE.MatchString(in.Key):
		return Plan{}, invalid("key", "invalid_key")
	case !validPlanName(in.Name):
		return Plan{}, invalid("name", "invalid_name")
	}
	if f := CheckPlanLimits(in.Limits, false); f != "" {
		return Plan{}, invalid(f, "invalid_limits")
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: a.IdentityID, OperationID: CreatePlanOperation, Key: idem.Key}
		var replay *Plan
		err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			d, err := jobs.BeginIdempotent(ctx, q, *key, idem.Hash, idempotencyLock)
			if errors.Is(err, jobs.ErrInvalidIdempotencyKey) {
				return invalid("Idempotency-Key", "invalid_idempotency_key")
			}
			if err != nil {
				return err
			}
			switch d.Outcome {
			case jobs.IdempotencyReplay:
				var v Plan
				if d.Response == nil || json.Unmarshal(d.Response.Body, &v) != nil {
					return errors.New("platform: stored plan response unreadable")
				}
				replay = &v
				return audit.Record(ctx, q, audit.Event{Action: ActionPlanCreate, ResourceType: "plan",
					ResourceID: v.ID.String(), Details: audit.Details{"replay": true}})
			case jobs.IdempotencyInProgress:
				return &AdminError{Kind: ErrIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
			case jobs.IdempotencyKeyReuse:
				return refuse(ErrIdempotencyKeyReuse, "idempotency_key_reuse")
			}
			return nil
		})
		if err != nil {
			return Plan{}, err
		}
		if replay != nil {
			return *replay, nil
		}
	}
	var out Plan
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		p, err := q.InsertPlan(ctx, sqlcdb.InsertPlanParams{Key: in.Key, Name: strings.TrimSpace(in.Name), Limits: in.Limits,
			IsActive: in.IsActive})
		switch store.SQLState(err) {
		case "23505":
			return refuse(ErrConflict, ReasonKeyTaken)
		case "23514":
			return invalid("limits", "invalid_limits")
		}
		if err != nil {
			return err
		}
		out = planView(p, 0)
		if err := audit.Record(ctx, q, audit.Event{Action: ActionPlanCreate, ResourceType: "plan", ResourceID: p.ID.String(),
			Details: audit.Details{"key": p.Key, "name": p.Name, "limits": string(p.Limits), "is_active": p.IsActive}}); err != nil {
			return err
		}
		if key == nil {
			return nil
		}
		body, err := json.Marshal(out)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 201, Body: body,
			Resource: &jobs.Resource{Type: "plan", ID: p.ID.String()}})
	})
	if err != nil {
		if key != nil {
			_ = s.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
				return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
			})
		}
		return Plan{}, err
	}
	return out, nil
}

// PlanPatch is PATCH /platform/plans/{id}; nil = unchanged (Limits replaces the whole document).
type PlanPatch struct {
	Name     *string
	Limits   []byte
	IsActive *bool
}

// UpdatePlan is PATCH /platform/plans/{id} (If-Match).
func (s *Service) UpdatePlan(ctx context.Context, id uuid.UUID, p PlanPatch, ifMatch string) (Plan, error) {
	if p.Name == nil && p.Limits == nil && p.IsActive == nil {
		return Plan{}, invalid("body", ReasonEmpty)
	}
	if p.Name != nil && !validPlanName(*p.Name) {
		return Plan{}, invalid("name", "invalid_name")
	}
	if p.Limits != nil {
		if f := CheckPlanLimits(p.Limits, false); f != "" {
			return Plan{}, invalid(f, "invalid_limits")
		}
	}
	var out Plan
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		cur, err := q.LockPlan(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := ifMatchVersion(ifMatch, cur.Version); err != nil {
			return err
		}
		name, limits, active := cur.Name, cur.Limits, cur.IsActive
		if p.Name != nil {
			name = strings.TrimSpace(*p.Name)
		}
		if p.Limits != nil {
			limits = p.Limits
		}
		if p.IsActive != nil {
			active = *p.IsActive
		}
		np, err := q.UpdatePlan(ctx, sqlcdb.UpdatePlanParams{Name: name, Limits: limits, IsActive: active,
			Now: time.Now().UTC(), ID: id})
		if store.SQLState(err) == "23514" {
			return invalid("limits", "invalid_limits")
		}
		if err != nil {
			return err
		}
		r, err := q.GetPlanWithUsage(ctx, id)
		if err != nil {
			return err
		}
		out = planView(r.SubscriptionPlan, r.TenantCount)
		return audit.Record(ctx, q, audit.Event{Action: ActionPlanUpdate, ResourceType: "plan", ResourceID: id.String(),
			Details: audit.Details{"key": np.Key, "before_name": cur.Name, "after_name": np.Name,
				"before_limits": string(cur.Limits), "after_limits": string(np.Limits),
				"before_is_active": cur.IsActive, "after_is_active": np.IsActive}})
	})
	return out, err
}
