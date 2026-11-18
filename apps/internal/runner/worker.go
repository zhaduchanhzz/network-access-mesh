package runner

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/auditsync"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/external"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// partitionRole is the owner of the partitioned tables, used only by partition.maintain (§6.1).
const partitionRole = "mg_partition_maint"

// buildWorker wires the worker process (P2-T16):
//
//	store            mg_worker_tenant / mg_worker_platform (§6.1); SecretStore with kek-app AND kek-ops (§7.6)
//	jobs.Worker      jobs.DefaultConfig (every timeout explicit — §11.3); built-in job.reaper, retention.sweep and,
//	                 with the mg_partition_maint pool, partition.maintain (daily); Alerter = fan-out to devices.JobAlert
//	devices          inventory.sync + device.revoke handlers, the inventory.sync schedule, JobAlert (P2-T13)
//	monitoring       health.probe handler over the Headscale registry's Probe, its schedule (P2-T13a)
//	identity         session.gc on the worker's store, scheduled through jobs.Worker.RegisterPeriodic (P2-T06)
//	notifications    notification.send over the SMTP relay of MG_SMTP_* (none configured ⇒ e-mail rows cancelled,
//	                 Portal records kept — refused in production by config) — P3-T05b
//	reconcile        instance.reconcile + host.reconcile, report only, and their schedule (P3-T12; agent: MG_AGENT_*)
//	apikey           apikey.rotate (P3-T10): its handler, its daily schedule per instance and the key expiry gauge
//	orchestrator     tenant.provision — the 19 steps of §11.3 with compensation (P3-T05; MG_PROVISION_*, MG_PROBER_URL,
//	                 the same agent client as reconcile); instance.reconfigure (P3-T13: MG_AGENT_* — prober optional)
//	lifecycle        tenant.suspend + tenant.resume (P3-T08, §11.4) over a Headscale registry of their own that reaches a
//	                 suspended tenant's instance (lifecycle.go), always wired — no Host Agent needed
//	relay            relay.probe + its schedule over the prober (P3-T05c; MG_PROBER_URL towards MG_PROVISION_EDGE_ADDR —
//	                 without a prober nothing is probed and the relay read models say never_checked/stale)
//	idp              driver registry keycloak (narrow route to auth.<domain> incl. /admin/realms, provisioning identity
//	                 from the SecretStore — platform_ops) + external (hardened client) — P2-T05a; idp.audit_sync every
//	                 minute over the keycloak driver (admin + login events of every realm → audit_events, security
//	                 events, notifications — P3-T15, internal/idp/auditsync)
//	readiness        postgres, secretstore, edge_admin (§16.2)
func buildWorker(ctx context.Context, cfg config.Config, log *slog.Logger, reg prometheus.Registerer) (_ *component, err error) {
	d, err := openDeps(ctx, cfg, log, nil) // nil: idp.PlatformDriverPaths (public OIDC + Admin REST API)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			d.close()
		}
	}()
	part, err := store.OpenPartitionMaintainer(ctx, cfg.DB.URL, store.Credentials{User: partitionRole,
		PasswordFile: cfg.PartitionPasswordFile})
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, part.Close)
	dev, err := d.newDevices(reg)
	if err != nil {
		return nil, err
	}
	mon, err := monitoring.New(d.st, monitoring.Config{Devices: deviceCounter(dev), Prober: prober(d.headscale),
		Logger: log, Registerer: reg})
	if err != nil {
		return nil, err
	}
	w, err := jobs.NewWorker(d.st, jobs.DefaultConfig(), jobs.Options{Logger: log, Registerer: reg,
		Alerter: fanOut{dev}, Partitions: part})
	if err != nil {
		return nil, err
	}
	if err := dev.Register(w); err != nil {
		return nil, err
	}
	if err := mon.Register(w); err != nil {
		return nil, err
	}
	if err := identity.NewSessionGC(d.st, log, nil).Register(w); err != nil {
		return nil, err
	}
	sender, err := newNotificationSender(cfg, d.st, log)
	if err != nil {
		return nil, err
	}
	if err := sender.Register(w); err != nil {
		return nil, err
	}
	life, err := newLifecycle(cfg, d) // P3-T08: tenant.suspend + tenant.resume
	if err != nil {
		return nil, err
	}
	if err := life.Register(w); err != nil {
		return nil, err
	}
	agent, err := newAgent(cfg, d) // one client of the Host Agent: reconcile + orchestrator
	if err != nil {
		return nil, err
	}
	rec, err := newReconcile(d, agent, reg) // P3-T12: instance.reconcile + host.reconcile, report only
	if err != nil {
		return nil, err
	}
	if err := rec.Register(w); err != nil {
		return nil, err
	}
	keys, err := newAPIKeyRotation(cfg, d, reg) // P3-T10: apikey.rotate + its schedule and expiry gauge
	if err != nil {
		return nil, err
	}
	if err := keys.Register(w); err != nil {
		return nil, err
	}
	drivers, kc, provisioned, err := idpDrivers(ctx, cfg, d)
	if err != nil {
		return nil, err
	}
	audits, err := auditsync.New(d.st, auditsync.Config{Source: kc, Logger: log, Registerer: reg})
	if err != nil {
		return nil, err
	}
	if err := w.RegisterPeriodic(auditsync.JobKind, auditsync.Interval, audits.Run); err != nil {
		return nil, err
	}
	relays, err := NewRelayProbe(cfg, d.st, log, reg) // P3-T05c: relay.probe (nil without MG_PROBER_URL)
	if err != nil {
		return nil, err
	}
	if relays != nil {
		if err := relays.Register(w); err != nil {
			return nil, err
		}
	}
	prov, err := newProvisioner(cfg, d, agent, drivers) // P3-T05: tenant.provision (19 steps of §11.3)
	if err != nil {
		return nil, err
	}
	if prov != nil {
		if err := prov.Register(w); err != nil {
			return nil, err
		}
	}
	rcfg, err := newReconfigurer(cfg, d, agent) // P3-T13: instance.reconfigure (new version, restart, health gate, rollback)
	if err != nil {
		return nil, err
	}
	if rcfg != nil {
		if err := rcfg.Register(w); err != nil {
			return nil, err
		}
	}
	log.Info("worker wired", "idp_drivers", drivers.Names(), "keycloak_provisioner_bootstrapped", provisioned)
	if !provisioned {
		log.Warn("the keycloak driver's provisioning identity is not bootstrapped yet: run `meshguard-worker admin " +
			"idp-bootstrap` (RUNBOOK), then restart the worker — no Phase 2 job uses the driver")
	}

	var wg sync.WaitGroup
	sched, cancel := context.WithCancel(context.Background())
	c := &component{probes: d.probes(), close: d.close}
	c.start = func(ctx context.Context) error {
		if err := w.Start(ctx); err != nil {
			cancel()
			return err
		}
		for name, run := range map[string]func(context.Context) error{
			"inventory.sync": dev.NewScheduler(devices.SchedulerConfig{}).Run,
			"health.probe":   mon.NewScheduler(monitoring.SchedulerConfig{}).Run,
			"reconcile":      rec.NewScheduler(reconcile.SchedulerConfig{}).Run,
			"apikey.rotate":  keys.NewScheduler(apikey.SchedulerConfig{}).Run,
			"relay.probe":    relaySchedule(relays),
		} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := run(sched); err != nil && !errors.Is(err, context.Canceled) {
					log.Error("schedule stopped", "schedule", name, "error", err.Error())
				}
			}()
		}
		return nil
	}
	c.stop = func(ctx context.Context) {
		cancel()
		wg.Wait()
		if err := w.Stop(ctx); err != nil {
			log.Warn("job worker stop", "error", err.Error())
		}
	}
	return c, nil
}

// fanOut forwards every job alert (already counted and logged by the worker) to the modules that settle their own
// failed jobs: devices (failed revocations, the audit pair of an API-requested sync — P2-T13).
type fanOut []jobs.Alerter

func (f fanOut) JobAlert(ctx context.Context, a jobs.Alert) {
	for _, x := range f {
		x.JobAlert(ctx, a)
	}
}

// prober adapts the Headscale registry's Probe to monitoring (which does not import internal/headscale — §13.6).
func prober(reg *headscale.CachingRegistry) monitoring.Prober {
	return monitoring.ProberFunc(func(ctx context.Context, t uuid.UUID) monitoring.InstanceProbe {
		p := reg.Probe(ctx, t)
		return monitoring.InstanceProbe{InstanceID: p.InstanceID, Version: p.Version, Database: p.Database,
			Breaker: string(p.Breaker), Reason: p.Reason(), Duration: p.Duration}
	})
}

// idpDrivers builds the IdP driver registry of the worker (P2-T05a): keycloak over the narrow platform route with the
// provisioning identity stored by `meshguard-worker admin idp-bootstrap` (its latest secret version in the SecretStore,
// platform_ops — never in the configuration) and external over the hardened client. provisioned is false while the
// provisioning identity has not been bootstrapped: the driver then points at version 1 of its reference and its calls
// fail until the bootstrap ran and the worker restarted.
func idpDrivers(ctx context.Context, cfg config.Config, d *deps) (_ *idp.Registry, _ *keycloak.Driver, provisioned bool, err error) {
	clientID := cfg.IdPProvisionerClientID
	if clientID == "" {
		clientID = keycloak.DefaultProvisionerClientID
	}
	ref, err := d.secrets.Latest(ctx, uuid.Nil, keycloak.ProvisionerRefName)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		ref = secrets.PlatformRef(keycloak.ProvisionerRefName, 1)
	case err != nil:
		return nil, nil, false, err
	default:
		provisioned = true
	}
	sec := platformSecurity{st: d.st} // G2 F3: a client_secret_ref that is not the IdP's own ⇒ security event
	kc, err := keycloak.New(keycloak.Config{Route: d.route, Secrets: d.secrets,
		Provisioner: keycloak.Credentials{ClientID: clientID, Secret: ref},
		AppHost:     cfg.AppHost(), AdminHost: cfg.AdminHost(), Logger: d.log, Security: sec})
	if err != nil {
		return nil, nil, false, err
	}
	ext, err := external.New(external.Config{Client: d.hardened, Secrets: d.secrets, Security: sec})
	if err != nil {
		return nil, nil, false, err
	}
	r, err := idp.NewRegistry(kc, ext)
	return r, kc, provisioned, err
}

// platformSecurity records the security events of the IdP drivers (idp.SecurityRecorder — G2 F3) in a platform
// transaction of the worker's own store, like integrityReporter: the worker has no audit.Logger (no audit writer pool
// — P2-T16 decision 8), and a security event is a plain row of security_events, written with dedupe.
type platformSecurity struct{ st *store.Store }

var _ idp.SecurityRecorder = platformSecurity{}

func (p platformSecurity) RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error) {
	var recorded bool
	err := p.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		recorded, err = audit.RecordSecurityEvent(ctx, q, ev)
		return err
	})
	return recorded, err
}

// newNotificationSender builds the notification.send handler (P3-T05b): the SMTP relay of MG_SMTP_* (nil mailer when
// MG_SMTP_ADDR is unset), the Portal and Console links of the templates from MG_BASE_DOMAIN.
func newNotificationSender(cfg config.Config, st *store.Store, log *slog.Logger) (*notifications.Sender, error) {
	sc := notifications.SenderConfig{Logger: log, MessageIDDomain: cfg.BaseDomain}
	if h := cfg.AppHost(); h != "" {
		sc.PortalURL = "https://" + h
	}
	if h := cfg.AdminHost(); h != "" {
		sc.ConsoleURL = "https://" + h
	}
	if cfg.SMTP.Addr != "" {
		mc := notifications.SMTPConfig{Addr: cfg.SMTP.Addr, TLS: cfg.SMTP.TLS, ServerName: cfg.SMTP.ServerName,
			Username: cfg.SMTP.Username, PasswordFile: cfg.SMTP.PasswordFile, From: cfg.SMTP.From}
		if cfg.SMTP.CAFile != "" {
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			pem, err := os.ReadFile(cfg.SMTP.CAFile) //nolint:gosec // G304: deployment configuration (MG_SMTP_CA_FILE)
			if err != nil || !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("MG_SMTP_CA_FILE: no PEM certificate could be read from %s", cfg.SMTP.CAFile)
			}
			mc.RootCAs = pool
		}
		m, err := notifications.NewSMTPMailer(mc)
		if err != nil {
			return nil, err
		}
		sc.Mailer = m
		if d := m.FromDomain(); d != "" {
			sc.MessageIDDomain = d
		}
		log.Info("notification relay configured", "smtp_addr", cfg.SMTP.Addr, "tls", cfg.SMTP.TLS,
			"auth", cfg.SMTP.Username != "")
	}
	return notifications.NewSender(st, sc)
}
