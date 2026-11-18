//go:build linux && dockerintegration

package provisioning

// One worker process of the harness (PIT_ROLE=worker): the production wiring of tenant.provision
// (apps/internal/runner/provision.go — DBStore, platform.Placer, the SecretStore, the Headscale registry through the
// edge locator, the Host Agent client over its socket, jobs.Worker with River) and of tenant.deprovision
// (apps/internal/runner/deprovision.go — the backup service for the final backup, a registry reaching deprovisioning
// tenants, the policy core over it; P3-T09) with every collaborator wrapped by faultinject per the plan in PIT_FAULTS. It runs as the worker's identity (UID 65532, group 20003) so the agent
// accepts it (SO_PEERCRED). SIGTERM: graceful stop. A kill fault: SIGKILL to itself, after the real call returned.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/deprovision"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/faultinject"
)

// Markers on the worker's output the harness reads.
const (
	markReady   = "PIT-WORKER-READY"
	markFault   = "PIT-FAULT "
	markSummary = "PIT-WORKER-SUMMARY "
)

// securityRecorder records security events in the platform scope (apps/internal/runner platformSecurity).
type securityRecorder struct{ st *store.Store }

func (s securityRecorder) RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error) {
	var recorded bool
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		recorded, err = audit.RecordSecurityEvent(ctx, q, ev)
		return err
	})
	return recorded, err
}

// workerJobsConfig is the production job configuration with the waits of a test (polling, backoff, reaper).
func workerJobsConfig() jobs.Config {
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 20*time.Millisecond, 200*time.Millisecond
	cfg.RetryBase, cfg.RetryMax = 100*time.Millisecond, 500*time.Millisecond
	cfg.LockBusySnooze, cfg.LockHeldSnooze = 500*time.Millisecond, time.Second
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 5*time.Second, 4
	cfg.ReaperInterval, cfg.ReaperMinAge = 2*time.Second, time.Second
	return cfg
}

func TestWorkerProcess(t *testing.T) {
	if os.Getenv("PIT_ROLE") != "worker" {
		t.Skip("a worker process of the harness (started by TestProvisioningFaultInjection with PIT_ROLE=worker)")
	}
	e := mustEnv(t)
	plan, err := faultinject.ParsePlan(os.Getenv("PIT_FAULTS"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	pg := storetest.Require(t)
	st := pg.OpenStore(t, os.Getenv("PIT_DB"), "mg_worker_tenant", "mg_worker_platform", 12)
	kr, err := secrets.LoadKeyring(secrets.KEKApp, os.Getenv("PIT_KEYRING"))
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(st, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := agentclient.New(agentclient.Config{Socket: e.socket(), TokenFile: e.agentTokenFile()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = agent.Close() }()
	loc, err := locator.New(tenants.New(st, tenants.Options{BaseDomain: e.baseDomain}), sec,
		locator.Options{AdminURL: e.edgeAdmin, EdgeTokenFile: e.edgeTokenFile(), Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	placer, err := platform.NewPlacer(st, platform.PlacerOptions{BaseDomain: e.baseDomain, TenantsDir: e.tenantsDir()})
	if err != nil {
		t.Fatal(err)
	}
	in, err := faultinject.New(plan, faultinject.Options{
		Notify: func(ev faultinject.Event) {
			b, _ := json.Marshal(ev)
			fmt.Fprintln(os.Stderr, markFault+string(b))
		},
		Kill: func() {
			fmt.Fprintln(os.Stderr, markFault+`{"killed":true}`)
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {} // the kernel ends the process
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := headscale.NewRegistry(loc, headscale.Options{Logger: log})
	kc := &keycloakDriver{sec: sec, realms: map[string]string{}} // one in-memory IdP for both jobs of the process
	p, err := orchestrator.New(orchestrator.Config{
		Store:     &faultinject.Store{Store: orchestrator.NewDBStore(st, nil), In: in},
		Agent:     &faultinject.Agent{Next: agent, In: in},
		Placer:    &faultinject.Placer{Next: placer, In: in},
		Secrets:   &faultinject.Secrets{SecretStore: sec, In: in},
		IdP:       &faultinject.IdP{Next: drivers{idp.DriverKeycloak: kc}, In: in},
		Headscale: &faultinject.Headscale{Next: reg, In: in},
		Prober:    &faultinject.Prober{Next: newEdgeProber(), In: in},
		Security:  securityRecorder{st: st},
		Logger:    log,
		// the runtime of new instances: [images.mg-headscale] (allowlisted by the agent) and [images.headscale].tag
		HeadscaleDigest: e.hsDigest, HeadscaleVersion: e.hsVersion,
		Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, EdgeAddress: e.edgePublic,
		MemoryMiB: 256, CPUMillis: 500, PIDs: 128,
		RetryBase: 100 * time.Millisecond, RetryMax: 500 * time.Millisecond, HealthPoll: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := jobs.NewWorker(st, workerJobsConfig(), jobs.Options{Logger: log, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Register(w); err != nil {
		t.Fatal(err)
	}
	// tenant.deprovision (P3-T09): the final backup through the real backup service and agent, a registry that reaches a
	// deprovisioning tenant (deprovision.ReachableStatuses — like apps/internal/runner/deprovision.go), the policy core
	// over it, the shortened key grace of the run
	bk := backup.New(st, backup.Config{Agent: &faultinject.BackupAgent{Next: agent, In: in}, Secrets: sec, Registry: reg,
		ManifestKeys: e.manifestKeys, Logger: log})
	dloc, err := locator.New(tenants.New(st, tenants.Options{BaseDomain: e.baseDomain}), sec,
		locator.Options{AdminURL: e.edgeAdmin, EdgeTokenFile: e.edgeTokenFile(), TenantStatuses: deprovision.ReachableStatuses, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	dreg := headscale.NewRegistry(dloc, headscale.Options{Logger: log})
	core, err := policies.New(st, policies.Config{Registry: dreg, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	dep, err := deprovision.New(deprovision.Config{Store: st, Agent: &faultinject.Agent{Next: agent, In: in}, Backups: bk,
		Secrets: sec, IdP: &faultinject.IdP{Next: drivers{idp.DriverKeycloak: kc}, In: in}, Policies: core,
		Headscale: &faultinject.Headscale{Next: dreg, In: in}, Security: securityRecorder{st: st}, Logger: log,
		KeyGrace: e.keyGrace, RetryBase: 100 * time.Millisecond, RetryMax: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := dep.Register(w); err != nil {
		t.Fatal(err)
	}
	// instance.backup + instance.restore (P3-T11), instance.reconfigure (P3-T13) and instance.restart (P3-T13a), as the
	// worker wires them: E2E-84 (P3-T14b) runs them on an instance built by hand, adopted and backfilled
	if err := bk.Register(w); err != nil {
		t.Fatal(err)
	}
	rc, err := orchestrator.NewReconfigurer(orchestrator.ReconfigureConfig{Store: orchestrator.NewDBStore(st, nil), Agent: agent,
		Headscale: reg, Prober: newEdgeProber(), Security: securityRecorder{st: st}, Logger: log, EdgeAddress: e.edgePublic,
		RetryBase: 100 * time.Millisecond, RetryMax: 500 * time.Millisecond, HealthPoll: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Register(w); err != nil {
		t.Fatal(err)
	}
	rs, err := orchestrator.NewRestarter(orchestrator.InstanceOpsConfig{Store: orchestrator.NewDBStore(st, nil), Agent: agent,
		Headscale: reg, Policies: core, Prober: newEdgeProber(), Security: securityRecorder{st: st}, Logger: log,
		EdgeAddress: e.edgePublic, RetryBase: 100 * time.Millisecond, RetryMax: 500 * time.Millisecond, HealthPoll: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Register(w); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fmt.Println(markReady)
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := w.Stop(sctx); err != nil {
		t.Logf("worker stop: %v", err)
	}
	fmt.Fprintln(os.Stderr, markSummary+in.Summary())
}
