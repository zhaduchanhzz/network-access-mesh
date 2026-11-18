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
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/backupapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/devicesapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/hostsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/idpconsoleapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/invitationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/jobsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/lifecycleapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/monitoringapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/notificationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/provisioningapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/reconfigureapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/relayapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
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
//	                 session (P3-T15) — P3-T09/T11/T18 add theirs
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
//	                 Reconfigure (reconfigureapi over orchestrator.ReconfigureService — instance.reconfigure, P3-T13)
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
	dev, err := d.newDevices(reg)
	if err != nil {
		return nil, err
	}
	mon, err := monitoring.New(d.st, monitoring.Config{Devices: deviceCounter(dev), Logger: log, Registerer: reg})
	if err != nil {
		return nil, err
	}
	backups := backup.New(d.st, backup.Config{Logger: log}) // P3-T11: the api enqueues; the worker runs the jobs
	actions, err := approvalActions(backups)
	if err != nil {
		return nil, err
	}
	authorizer := authz.New(d.st)
	appr, err := approvals.New(d.st, approvals.Config{Approvers: authorizer, Registry: actions, Security: auditLog,
		Logger: log})
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
	hooks := authzhook.Hooks(svc, authorizer)
	hooks.Audit = auditapi.Middleware(auditLog)
	gate := idpconsoleapi.NewGate(idpconsoleapi.GateConfig{Grants: console.NewStore(d.st), Authz: authorizer,
		Audit: auditLog, Logger: log})
	public, err := httpapi.New(httpapi.Options{
		Logger:         log,
		TrustedProxies: cfg.TrustedProxies,
		Hooks:          hooks,
		Internal:       map[string]http.Handler{"GET " + idpconsoleapi.GatePath: gate},
		Handlers: httpapi.Handlers{
			Auth:          identityapi.New(svc),
			Tenants:       tenantsapi.New(d.tenants, platform.New(d.st)),
			Devices:       devicesapi.New(dev),
			Audit:         auditapi.New(audit.NewReader(d.st)),
			Jobs:          jobsapi.New(jobs.NewService(d.st)),
			Monitoring:    monitoringapi.New(mon),
			Notifications: notificationsapi.New(notifications.NewReader(d.st)),
			Approvals:     approvalsapi.New(appr),
			Backups:       backupapi.New(backups, appr),
			Invitations:   invitationsapi.New(d.tenants, authz.GuardInvitationRole),
			Hosts:         hostsapi.New(platform.New(d.st)),
			IdPConsole:    idpconsoleapi.New(appr),
			Provisioning:  provisioningapi.New(creator, orchestrator.NewControl(d.st)),
			Lifecycle:     lifecycleapi.New(lifecycle.NewRequester(d.st)),
			Relay:         relayapi.New(relays),
			Reconfigure:   reconfigureapi.New(orchestrator.NewReconfigureService(d.st)),
		},
	})
	if err != nil {
		return nil, err
	}
	log.Info("api wired", "app_host", cfg.AppHost(), "admin_host", cfg.AdminHost(), "idp_platform_host",
		cfg.IdPPlatformHost(), "trusted_proxies", len(cfg.TrustedProxies), "egress_deny", len(cfg.EgressDeny))
	return &component{probes: d.probes(), public: edgeOnly(cfg.TrustedProxies, public), close: d.close}, nil
}

// approvalActions is the registry of the actions the api executes after a second person approved them (§8.5/§8.6 2P,
// P3-T04a): the Keycloak administration console session (P3-T15); the tasks that build the other 2P operations add
// theirs — deprovision (P3-T09), restore (P3-T11), release (P3-T18), Super Admin role and tenant IdP changes (P4-T03a),
// break-glass (P4-T13). A request of an action not registered here can be read and rejected, never approved (409
// action_unavailable).
func approvalActions(backups *backup.Service) (*approvals.Registry, error) {
	return approvals.NewRegistry(consoleSessionAction(), restoreAction(backups))
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
