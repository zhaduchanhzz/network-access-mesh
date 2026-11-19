package policies

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// ResourceReferences counts the policy versions that can still be applied (not superseded or rejected, or the desired
// one) whose typed source names the network resource (principal {type: resource, ref: <id>} — §7.2, P4-T10), in the
// caller's transaction q. The network module refuses to delete a resource still named (P4-T12: the next policy.apply
// would fail L6); it calls this through a function wired in apps/ (network may not import policies — §13.6).
func ResourceReferences(ctx context.Context, q *sqlcdb.Queries, tenantID, resourceID uuid.UUID) (int64, error) {
	rows, err := q.ListReferencingPolicyContents(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, r := range rows {
		if len(r.Source) == 0 {
			continue
		}
		var v any
		if json.Unmarshal(r.Source, &v) != nil {
			n++ // unreadable typed source: keep the resource
			continue
		}
		if namesResource(v, resourceID.String()) {
			n++
		}
	}
	return n, nil
}

func namesResource(v any, id string) bool {
	switch t := v.(type) {
	case map[string]any:
		if t["type"] == PrincipalResource && t["ref"] == id {
			return true
		}
		for _, x := range t {
			if namesResource(x, id) {
				return true
			}
		}
	case []any:
		for _, x := range t {
			if namesResource(x, id) {
				return true
			}
		}
	}
	return false
}
