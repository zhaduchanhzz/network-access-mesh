package runner

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/adminapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/backupapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/deprovisionapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/devicesapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/enrollmentapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/hostsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/idpconsoleapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/instanceopsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/invitationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/jobsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/lifecycleapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/membersapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/monitoringapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/notificationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/provisioningapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/quarantineapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/reconfigureapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/relayapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tagsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/members"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/deprovision"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/quarantine"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
)

// buildAPI wires the api process (P2-T16) — the public REST API (/api/v1, §13) behind the middleware chain of P2-T14:
//
//	store            mg_api_tenant / mg_api_platform (§6.1); SecretStore with kek-app only (§7.6)
//	audit            audit.Logger over the store and the detached writer mg_audit_writer (P2-T08)
//	identity         OIDC RP + BFF session (P2-T06): app./admin. origins, the issuer client = hardened client + the
//	                 narrow route to auth.<domain> restricted to the public OIDC endpoints (P2-T05a), client secrets from
//	                 the SecretStore, its audit through auditapi.IdentityAuditor, request id / client IP / problems of
//	                 the httpapi chain (authzhook — P2-T15a); the first login of a tenant identity is bound to the
//	                 pending invitation of its tenant by tenants.Service (P3-T05a)
//	approvals        dual control (P3-T04a): authz.Authorizer decides the second person, the audit Logger raises the
//	                 security events; the registry of executable actions (approvalActions): the Keycloak console
//	                 session (P3-T15), the release of a quarantined instance (P3-T18) — P3-T09/T11 add theirs
//	idp console      the gate of the Keycloak administration console (P3-T15): GET /internal/edge/idp-console, the
//	                 forward_auth of the edge on admin.<domain> (httpapi.Options.Internal), over the console grants
//	                 (approval_requests), the authorizer and the audit Logger
//	hooks            Session = identity middleware, Authz = authz.New(store) (P2-T07), Audit = auditapi.Middleware
//	handlers         Auth (identityapi), Tenants (tenantsapi over tenants + platform), Devices (devicesapi over devices
//	                 + the Headscale registry), Audit (auditapi over audit.Reader), Jobs (jobsapi over jobs.Service),
//	                 Monitoring (monitoringapi over monitoring, reads only — the worker probes), Hosts (hostsapi over
//	                 platform — P3-T04), Notifications (notificationsapi over notifications.Reader — the caller's
//	                 own Portal notifications, P3-T05b), Approvals (approvalsapi over approvals), Invitations
//	                 (invitationsapi over tenants + authz.GuardInvitationRole), IdPConsole (idpconsoleapi over
//	                 approvals — P3-T15), Provisioning (provisioningapi over orchestrator.Creator — steps 1–2 of
//	                 tenant.provision with usage's quota checks — and orchestrator.Control, P3-T05), Lifecycle
//	                 (lifecycleapi over lifecycle.Requester — suspend/resume, P3-T08), Relay (relayapi over relay —
//	                 the tenant's relays and the platform's regions with the last probe, reads only, P3-T05c),
//	                 Reconfigure (reconfigureapi over orchestrator.ReconfigureService — instance.reconfigure, P3-T13),
//	                 InstanceOps (instanceopsapi over orchestrator.InstanceOpsService — instance.restart and
//	                 instance.upgrade, P3-T13a)
//	                 Quarantine (quarantineapi over quarantine.Requester + approvals — quarantine at once, release 2P,
//	                 P3-T18), Tags (tagsapi over policies.TagService — the tag catalog, P4-T15; the same catalog checks
//	                 PUT /devices/{id}/tags in devices), Portal (the same notificationsapi handlers — the read state of
//	                 the caller's own Portal notifications, P4-T04)
//	maintenance      the gate of P3-T17 (MG_MAINTENANCE OR system_settings maintenance, polled): 503 maintenance to
//	                 everything but the platform sign-in on admin.<domain> (httpapi.Options.Maintenance)
//	readiness        postgres, secretstore, edge_admin (§16.2)
func buildAPI(ctx context.Context, cfg config.Config, log *slog.Logger, reg prometheus.Registerer) (_ *component, err error) {
	d, err := openDeps(ctx, cfg, log, idp.PlatformOIDCPaths)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			d.close()
		}
	}()
	writer, err := store.OpenAuditWriter(ctx, cfg.DB.URL, store.Credentials{User: store.AuditWriterRole,
		PasswordFile: cfg.AuditWriterPasswordFile})
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, writer.Close)
	auditLog, err := audit.New(d.st, writer, audit.Config{Log: log, Registerer: reg})
	if err != nil {
		return nil, err
	}
	svc, err := identity.New(d.st, identity.Config{
		AppHost: cfg.AppHost(), AdminHost: cfg.AdminHost(),
		HTTPClient:    idp.NewIssuerClient(d.hardened, d.route),
		ClientSecrets: clientSecrets(d.secrets, d.tenants),
		Auditor:       auditapi.IdentityAuditor(auditLog),
		Invitations:   d.tenants,
		Logger:        log,
		ClientIP:      authzhook.ClientIP,
		RequestID:     authzhook.RequestID,
		ProblemWriter: authzhook.WriteProblem,
	})
	if err != nil {
		return nil, err
	}
	tags, err := policies.NewTags(d.st, policies.TagsConfig{}) // P4-T15: the tag catalog (CRUD + catalog checks)
	if err != nil {
		return nil, err
	}
	dev, err := d.newDevices(reg, tags)
	if err != nil {
		return nil, err
	}
	mon, err := monitoring.New(d.st, monitoring.Config{Devices: deviceCounter(dev), Logger: log, Registerer: reg})
	if err != nil {
		return nil, err
	}
	backups := backup.New(d.st, backup.Config{Logger: log})                                                // P3-T11: the api enqueues; the worker runs the jobs
	deprov := deprovision.NewRequester(d.st)                                                               // P3-T09: the api checks and enqueues; the worker deprovisions
	mem, err := members.New(d.st, members.Config{Tenants: d.tenants, Guard: MembershipGuard, Logger: log}) // P4-T09
	if err != nil {
		return nil, err
	}
	plat := platform.New(d.st) // P4-T03a: platform administration (users, settings, plans, IdPs, tenant registry fields)
	actions, err := approvalActions(backups, deprov, mem, plat, d.tenants)
	if err != nil {
		return nil, err
	}
	authorizer := authz.New(d.st)
	enr, err := newEnrollment(d, true) // P4-T06: requests, approval, keys, web-auth claim, instructions
	if err != nil {
		return nil, err
	}
	appr, err := approvals.New(d.st, approvals.Config{Approvers: authorizer, Registry: actions, Security: auditLog,
		Logger: log, Notify: notifyDeciders})
	if err != nil {
		return nil, err
	}
	relays, err := relay.New(d.st, relay.Config{Logger: log, Registerer: reg}) // reads only — the worker probes
	if err != nil {
		return nil, err
	}
	creator, err := orchestrator.NewCreator(orchestrator.CreatorConfig{Store: d.st, Secrets: d.secrets,
		Quota: usage.NewChecker(d.st), QuotaTx: usage.TenantCreationTx, BaseDomain: cfg.BaseDomain})
	if err != nil {
		return nil, err
	}
	gate, err := newMaintenanceGate(ctx, cfg, d.st, log, reg) // P3-T17: 503 maintenance but the platform sign-in
	if err != nil {
		return nil, err
	}
	hooks := authzhook.Hooks(svc, authorizer)
	hooks.Audit = auditapi.Middleware(auditLog)
	consoleGate := idpconsoleapi.NewGate(idpconsoleapi.GateConfig{Grants: console.NewStore(d.st), Authz: authorizer,
		Audit: auditLog, Logger: log})
	inbox := notificationsapi.New(notifications.NewReader(d.st)) // P3-T05b list + P4-T04 read state
	public, err := httpapi.New(httpapi.Options{
		Logger:         log,
		TrustedProxies: cfg.TrustedProxies,
		Hooks:          hooks,
		Internal:       map[string]http.Handler{"GET " + idpconsoleapi.GatePath: consoleGate},
		Maintenance:    httpapi.Maintenance{On: gate.On, AdminHost: cfg.AdminHost()},
		Handlers: httpapi.Handlers{
			Auth:          identityapi.New(svc),
			Tenants:       tenantsapi.New(d.tenants, platform.New(d.st)),
			Devices:       devicesapi.New(dev),
			Tags:          tagsapi.New(tags, devicesapi.New(dev)),
			Audit:         auditapi.New(audit.NewReader(d.st)),
			Jobs:          jobsapi.New(jobs.NewService(d.st)),
			Monitoring:    monitoringapi.New(mon),
			Notifications: inbox,
			Approvals:     approvalsapi.New(appr),
			Backups:       backupapi.New(backups, appr),
			Invitations:   invitationsapi.New(d.tenants, authz.GuardInvitationRole),
			Hosts:         hostsapi.New(platform.New(d.st)),
			IdPConsole:    idpconsoleapi.New(appr),
			Provisioning:  provisioningapi.New(creator, orchestrator.NewControl(d.st).WithQuota(usage.TenantCreationTx)),
			Lifecycle:     lifecycleapi.New(lifecycle.NewRequester(d.st)),
			Relay:         relayapi.New(relays),
			Reconfigure:   reconfigureapi.New(orchestrator.NewReconfigureService(d.st)),
			InstanceOps:   instanceopsapi.New(orchestrator.NewInstanceOpsService(d.st)),
			Deprovision:   deprovisionapi.New(deprov, appr),
			Quarantine:    quarantineapi.New(quarantine.NewRequester(d.st), appr),
			Members:       membersapi.New(mem, appr),
			Portal:        inbox,                               // P4-T04: POST …/notifications/{id}/read
			Admin:         adminapi.New(plat, d.tenants, appr), // P4-T03a
			Enrollment:    enrollmentapi.New(enr, authorizer),  // P4-T06
		},
	})
	if err != nil {
		return nil, err
	}
	log.Info("api wired", "app_host", cfg.AppHost(), "admin_host", cfg.AdminHost(), "idp_platform_host",
		cfg.IdPPlatformHost(), "trusted_proxies", len(cfg.TrustedProxies), "egress_deny", len(cfg.EgressDeny))
	c := &component{probes: d.probes(), public: edgeOnly(cfg.TrustedProxies, public), close: d.close}
	var poll *background
	c.start = func(context.Context) error {
		poll = startBackground(func(ctx context.Context) { _ = gate.Run(ctx) })
		return nil
	}
	c.stop = func(context.Context) {
		if poll != nil {
			poll.stop()
		}
	}
	return c, nil
}

// approvalActions is the registry of the actions the api executes after a second person approved them (§8.5/§8.6 2P,
// P3-T04a): the Keycloak administration console session (P3-T15); the tasks that build the other 2P operations add
// theirs — deprovision (P3-T09), restore (P3-T11), release (P3-T18), Super Admin role and tenant IdP changes (P4-T03a),
// break-glass (P4-T13). A request of an action not registered here can be read and rejected, never approved (409
// action_unavailable).
func approvalActions(backups *backup.Service, deprov *deprovision.Requester, mem *members.Service, plat *platform.Service,
	ten *tenants.Service) (*approvals.Registry, error) {
	actions := []approvals.Action{consoleSessionAction(), restoreAction(backups), releaseAction(), deprovisionAction(deprov),
		groupMembersAction(mem)}
	return approvals.NewRegistry(append(actions, adminActions(plat, ten)...)...)
}

// MembershipGuard is authz.GuardMembershipChange as the members module takes it (members does not import authz —
// §13.6): §8.4 invariants 3, 3a and the last Owner, inside the transaction that writes the change (P4-T09).
func MembershipGuard(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, c members.Change) error {
	return authz.GuardMembershipChange(ctx, q, tenantID, authz.MembershipChange{Actor: c.Actor, Target: c.Target,
		NewRole: c.NewRole, Deactivate: c.Deactivate, OwnershipTransfer: c.OwnershipTransfer})
}

// groupMembersAction executes an approved change of a sensitive group's members (P4-T09, §7.3, §8.6): the approver
// held tenant.approval:decide and tenant.group:manage; the exact approved member set replaces the group's members and
// policy.apply (group_change) is enqueued in the approval's transaction. Without the members service (tests of the
// other actions) the action is registered and refuses to run.
func groupMembersAction(mem *members.Service) approvals.Action {
	return approvals.Typed(approvals.Spec{Name: members.ApprovalAction, Scope: authz.ScopeTenant, ResourceType: "group",
		Permission: "tenant.group:manage"},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, p members.GroupMembersPayload) (*uuid.UUID, error) {
			if mem == nil || e.Request.TenantID == nil {
				return nil, errors.New("group members: no members service in this process")
			}
			return mem.ExecuteGroupMembers(ctx, tx, *e.Request.TenantID, e.Request.ID, e.Request.ResourceID,
				e.Request.RequestedBy.IdentityID, p)
		})
}

// consoleSessionAction executes an approved console session (P3-T15, §8.2 (3)): the executed request IS the session —
// the console gate reads it (identity, source CIDR, window from the approval) — so nothing is enqueued; the execution
// raises the platform security event idp.console_session_opened (medium) in its transaction. A payload naming someone
// other than the requester is refused (rolled back: the request stays approved and never opens anything).
func consoleSessionAction() approvals.Action {
	return approvals.Typed(approvals.Spec{Name: console.Action, Scope: authz.ScopePlatform, ResourceType: console.ResourceType,
		Permission: console.Permission},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, p console.Payload) (*uuid.UUID, error) {
			if e.Request.RequestedBy.IdentityID != p.IdentityID {
				return nil, errors.New("console session: the payload names another person than the requester")
			}
			_, err := audit.RecordSecurityEvent(ctx, tx.Q, audit.SecurityEvent{Kind: console.KindSessionOpened,
				Severity: audit.SeverityMedium, Source: "approvals", Details: audit.Details{
					"approval_id": e.Request.ID, "identity_id": p.IdentityID, "source_cidr": p.SourceCIDR,
					"duration_minutes": p.DurationMinutes}})
			return nil, err
		})
}
