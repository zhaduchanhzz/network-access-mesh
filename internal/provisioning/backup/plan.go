package backup

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// maxPlanItems is the agent's bound of each list of a reconcile plan (agentspec.MaxListItems).
const maxPlanItems = 10000

var (
	machineKeyRE = regexp.MustCompile(`^mkey:[0-9a-f]{64}$`)
	tagRE        = regexp.MustCompile(`^tag:[a-z][a-z0-9-]{0,62}$`)
	hsUserRE     = regexp.MustCompile(`^mg-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// plan builds the ReconcilePlan of §17.2 step 5 from PostgreSQL as it is BEFORE the restore — always by machine key,
// never by numeric id (the restored id counter may hand an old id to another device — P2-T13):
//
//   - revoked: every live device PostgreSQL knows as expired (a revocation `expire` applied or pending, or an expiry
//     in the past at the last sync) — expired again in the restored database (expiring an expired node changes
//     nothing);
//   - deleted: every device removed after the backup was taken (deleted, or gone, after that time) whose machine key
//     is not live again — deleted again;
//   - nodes: the approved routes and tags of every live device (the desired state);
//   - offboarded users: the Headscale users of members whose membership is offboarded — their nodes expired.
//
// The "PostgreSQL older than the backup" branch has no list at all (§17.2 step 4: PostgreSQL knows nothing newer).
// The rows are returned too: the check step lists the live devices the restored instance no longer has (re-enroll).
func (s *Service) plan(ctx context.Context, tenantID uuid.UUID, v verified, older bool) (*agentv1.ReconcilePlan, []sqlcdb.ListRestorePlanDevicesRow, error) {
	var (
		rows []sqlcdb.ListRestorePlanDevicesRow
		gone []string
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		if rows, err = q.ListRestorePlanDevices(ctx, v.inst.ID); err != nil {
			return err
		}
		gone, err = q.ListOffboardedHeadscaleUsers(ctx)
		return err
	})
	if err != nil {
		return nil, nil, jobs.Transient("registry_unavailable", err)
	}
	p := &agentv1.ReconcilePlan{RestorePointOlderThanBackup: older}
	if older {
		return p, rows, nil
	}
	return p, rows, fillPlan(p, rows, gone, v.manifest.Time(), s.cfg.Now())
}

func fillPlan(p *agentv1.ReconcilePlan, rows []sqlcdb.ListRestorePlanDevicesRow, gone []string, backupAt, now time.Time) error {
	live := map[string]bool{}
	for _, r := range rows {
		if r.RemovedAt == nil && machineKeyRE.MatchString(r.MachineKey) {
			live[r.MachineKey] = true
		}
	}
	seen := map[string]bool{}
	revoked, deleted := map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		mk := r.MachineKey
		if !machineKeyRE.MatchString(mk) {
			continue
		}
		if r.RemovedAt != nil {
			if !live[mk] && !r.RemovedAt.Before(backupAt) {
				deleted[mk] = true
			}
			continue
		}
		expiredRevocation := r.RevocationKind != nil && *r.RevocationKind == "expire" &&
			(r.RevocationState == "applied" || r.RevocationState == "pending")
		if expiredRevocation || (r.Expiry != nil && !r.Expiry.After(now)) {
			revoked[mk] = true
		}
		if seen[mk] {
			continue
		}
		seen[mk] = true
		n := &agentv1.NodeDesiredState{MachineKey: mk}
		for _, pfx := range r.ApprovedRoutes {
			s := pfx.Masked().String()
			if !slices.Contains(n.ApprovedRoutes, s) {
				n.ApprovedRoutes = append(n.ApprovedRoutes, s)
			}
		}
		for _, t := range r.Tags {
			if tagRE.MatchString(t) && !slices.Contains(n.Tags, t) {
				n.Tags = append(n.Tags, t)
			}
		}
		p.Nodes = append(p.Nodes, n)
	}
	for mk := range revoked {
		p.RevokedMachineKeys = append(p.RevokedMachineKeys, mk)
	}
	for mk := range deleted {
		p.DeletedMachineKeys = append(p.DeletedMachineKeys, mk)
	}
	slices.Sort(p.RevokedMachineKeys)
	slices.Sort(p.DeletedMachineKeys)
	for _, u := range gone {
		if hsUserRE.MatchString(u) {
			p.OffboardedUsers = append(p.OffboardedUsers, u)
		}
	}
	if len(p.Nodes) > maxPlanItems || len(p.RevokedMachineKeys) > maxPlanItems || len(p.DeletedMachineKeys) > maxPlanItems ||
		len(p.OffboardedUsers) > maxPlanItems {
		return jobs.Permanent("plan_too_large", errors.New("the reconcile plan exceeds the agent's bounds"))
	}
	return nil
}
