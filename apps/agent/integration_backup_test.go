//go:build linux && dockerintegration

package main

// Integration test of backup/restore v1 (P3-T11; master §17.1–§17.2, §20 row P3-T11) on a real Docker Engine with the
// real helpers (static sqlite3 3.54.1 and age v1.3.2 of the agent image) and a real, patched Headscale 0.29.7 per
// tenant. No PostgreSQL, no worker: the test plays the worker (data key, plan). Covered here:
//
//   - §17.1: online backup by VACUUM INTO from a read-only mount while the instance writes (V-12), cold copy when the
//     instance is stopped; signed manifest; two key paths — the data key restores, the offline recovery identity
//     decrypts the very same archive with the age binary (DR path); A's archive holds no byte of B;
//   - T-15: B's data key does not open A's archive; a changed manifest, one signed by another key and A's archive placed
//     in B's directory are refused BEFORE anything is decrypted; B is untouched (AC-19: key hashes, normalised nodes/
//     users/policy, StartedAt);
//   - §17.2 + IT-16: restore after a rotation of the API key, a node revoked, a route unapproved, a member offboarded
//     and the policy tightened: the restored instance serves the applied policy, PostRestoreReconcile expires every
//     API key and pre-auth key of the archive, re-expires the revoked node, every node of the offboarded member, and
//     resets the route — all before the edge is attached again; a node registered after the backup is gone; the
//     restored id counters hand the gone node's and user's numeric ids to newcomers (another machine key; a pre-auth
//     key for the stale user id lands on the newcomer, the one for the id resolved by name on the right user);
//   - IT-15: a symlink to B's file, a FIFO, a huge sparse file and a corrupt database in A's data/ ⇒ backup and start
//     guard fail closed with a security event, no archive written, and the agent keeps serving B;
//   - V-12 again: the last backup taken under write load is restored and Headscale comes up healthy on it.

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
)

// hsNodeIT is what the test reads of `headscale nodes list -o json`.
type hsNodeIT struct {
	ID         uint64 `json:"id"`
	MachineKey string `json:"machine_key"`
	NodeKey    string `json:"node_key"`
	Name       string `json:"name"`
	User       *struct {
		Name string `json:"name"`
	} `json:"user"`
	Expiry *struct {
		Seconds int64 `json:"seconds"`
	} `json:"expiry"`
	ApprovedRoutes []string `json:"approved_routes"`
	Tags           []string `json:"tags"`
}

func (n hsNodeIT) expired() bool {
	return n.Expiry != nil && n.Expiry.Seconds > 0 && !time.Unix(n.Expiry.Seconds, 0).After(time.Now())
}

// hsUserIT is what the test reads of a Headscale user (`users create|list -o json`, the user of a pre-auth key).
type hsUserIT struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}

type hsKeyIT struct {
	ID         uint64 `json:"id"`
	Prefix     string `json:"prefix"`
	Key        string `json:"key"`
	Expiration *struct {
		Seconds int64 `json:"seconds"`
	} `json:"expiration"`
}

func (k hsKeyIT) valid() bool {
	return k.Expiration == nil || time.Unix(k.Expiration.Seconds, 0).After(time.Now())
}

func TestBackupRestoreEndToEnd(t *testing.T) {
	e := itConfig(t)
	ctx := context.Background()
	dc, err := client.New(client.WithHost("unix:///var/run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()
	eng, err := compose.NewEngine("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	before := observe(t, dc, e.root)

	// ---- the key ceremony of the test host: manifest signing key (PKCS#8 PEM, root 0400), recovery identity
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(e.root, "manifest_signing_key")
	write(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), 0o400)
	recoveryKey, _ := backupfmt.NewDataKey()
	recoveryPub, _ := backupfmt.DataRecipient(recoveryKey)
	recovery, _ := backupfmt.RecipientString(recoveryPub)
	recoveryID, _ := backupfmt.AgeIdentity(recoveryKey)
	idFile := filepath.Join(e.root, "recovery_identity")
	write(t, idFile, recoveryID+"\n", 0o400)
	t.Cleanup(func() { _ = os.Remove(keyFile); _ = os.Remove(idFile) })

	edgeName, edgeNet := e.prefix+"-edge", e.prefix+"-edgenet"
	a := startIT(ctx, t, e, map[string]string{"MG_AGENT_EDGE_CONTAINER": edgeName, "MG_AGENT_EDGE_NETWORK": edgeNet,
		"MG_AGENT_MANIFEST_SIGNING_KEY_FILE": keyFile, "MG_AGENT_BACKUP_RECOVERY_RECIPIENT": recovery,
		"MG_BACKUP_MANIFEST_PUBKEY":    backupfmt.PublicKeySPKI(signer.Public().(ed25519.PublicKey)),
		"MG_AGENT_BACKUP_MAX_DB_BYTES": strconv.Itoa(256 << 20), "MG_AGENT_BACKUP_TIMEOUT": "3m"})
	ac := a.client
	verifyKeys := []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}
	job := func() string { return uuid.NewString() }
	refusedAs := func(what string, err error, want agentv1.RefusalReason) {
		t.Helper()
		r, ok := agentclient.RefusalOf(err)
		if !ok || r.GetReason() != want {
			t.Fatalf("%s: %v, want %s", what, err, want)
		}
		t.Logf("%s: refused %s (%s)", what, r.GetReason(), r.GetMessage())
	}

	// ---- the fake edge (as in TestAgentOperationsEndToEnd)
	enr, err := dc.NetworkCreate(ctx, edgeNet, client.NetworkCreateOptions{Driver: "bridge",
		IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix(e.nets[7])}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), enr.ID, client.NetworkRemoveOptions{}) })
	cr, err := dc.ContainerCreate(ctx, client.ContainerCreateOptions{Name: edgeName,
		Config: &container.Config{Image: e.alpine, Cmd: []string{"sleep", "3600"}, User: "10001:10001", Labels: map[string]string{"meshguard.it": e.prefix}},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(edgeNet), ReadonlyRootfs: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{edgeNet: {GwPriority: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = dc.ContainerRemove(context.Background(), edgeName, client.ContainerRemoveOptions{Force: true})
	})
	if _, err := dc.ContainerStart(ctx, cr.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}

	// ---- tenants A and B
	_, digest, _ := strings.Cut(e.image, "@")
	tenant := func(suffix string, uid int, cidr string) itTenant {
		ref := &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: e.prefix + "-" + suffix}
		return itTenant{ref: ref, uid: uid, dir: filepath.Join(a.cfg.Host.TenantsDir, ref.GetInstanceId()),
			spec: &agentv1.InstanceSpec{Instance: ref, ImageDigest: digest, RunUid: uint32(uid), NetCidr: cidr, //nolint:gosec // G115: test
				Limits: &agentv1.ResourceLimits{MemoryMib: 256, CpuMillis: 500, Pids: 128},
				Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 90, Nameservers: []string{"192.0.2.53"}, DerpRegionId: 991,
					PublicEntryIpv4: "192.0.2.10", LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO}}}
	}
	ta, tb := tenant("ba", 39921, e.nets[4]), tenant("bb", 39922, e.nets[5])
	for _, x := range []itTenant{ta, tb} {
		t.Cleanup(func() {
			_, _ = ac.RemoveEdgeAttachment(context.Background(), &agentv1.RemoveEdgeAttachmentRequest{Instance: x.ref, JobId: job(),
				Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION})
			_, _ = ac.RemoveInstance(context.Background(), &agentv1.RemoveInstanceRequest{Instance: x.ref, JobId: job(),
				Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP})
			_ = os.RemoveAll(x.dir)
			_ = os.RemoveAll(filepath.Join(a.cfg.Host.BackupsDir, x.ref.GetInstanceId()))
		})
	}
	statusOf := func(x itTenant) *agentv1.InstanceStatus {
		t.Helper()
		r, err := ac.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{Instance: x.ref})
		if err != nil {
			t.Fatalf("GetInstanceStatus(%s): %v", x.ref.GetSlug(), err)
		}
		return r.GetStatus()
	}
	waitHealthy := func(x itTenant) {
		t.Helper()
		for start := time.Now(); time.Since(start) < 90*time.Second; time.Sleep(time.Second) {
			if statusOf(x).GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY {
				return
			}
		}
		t.Fatalf("%s not healthy after 90 s", x.ref.GetSlug())
	}
	hs := func(x itTenant, args ...string) []byte {
		t.Helper()
		res, err := eng.Exec(ctx, "mg-hs-"+x.ref.GetSlug(), append([]string{"headscale"}, args...), 30*time.Second)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("headscale %v: %v exit %d: %s", args, err, res.ExitCode, res.Stderr)
		}
		return res.Stdout
	}
	nodes := func(x itTenant) map[string]hsNodeIT {
		t.Helper()
		var l []hsNodeIT
		if err := json.Unmarshal(hs(x, "nodes", "list", "-o", "json"), &l); err != nil {
			t.Fatal(err)
		}
		out := map[string]hsNodeIT{}
		for _, n := range l {
			out[n.Name] = n
		}
		return out
	}
	apiKeys := func(x itTenant) []hsKeyIT {
		t.Helper()
		var l []hsKeyIT
		_ = json.Unmarshal(bytes.TrimSpace(hs(x, "apikeys", "list", "-o", "json")), &l)
		return l
	}
	preAuthKeys := func(x itTenant) []hsKeyIT {
		t.Helper()
		var l []hsKeyIT
		_ = json.Unmarshal(bytes.TrimSpace(hs(x, "preauthkeys", "list", "-o", "json")), &l)
		return l
	}
	newNode := func(x itTenant, user, name string, routes ...string) hsNodeIT {
		t.Helper()
		var b [12]byte
		_, _ = rand.Read(b[:])
		id := "hskey-authreq-" + hex.EncodeToString(b[:])
		args := []string{"debug", "create-node", "--user", user, "--name", name, "--key", id}
		for _, r := range routes {
			args = append(args, "--route", r)
		}
		hs(x, append(args, "-o", "json")...)
		hs(x, "auth", "register", "--auth-id", id, "--user", user, "-o", "json")
		n, ok := nodes(x)[name]
		if !ok {
			t.Fatalf("node %s not registered", name)
		}
		return n
	}
	up := func(x itTenant) string {
		t.Helper()
		for _, ph := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
			c, cancel := context.WithTimeout(ctx, 6*time.Minute)
			_, err := ac.EnsureInstance(c, &agentv1.EnsureInstanceRequest{Spec: x.spec, TargetPhase: ph, JobId: job()})
			cancel()
			if err != nil {
				t.Fatalf("EnsureInstance(%s): %v", x.ref.GetSlug(), err)
			}
		}
		waitHealthy(x)
		if _, err := ac.BootstrapPolicy(ctx, &agentv1.BootstrapPolicyRequest{Instance: x.ref, JobId: job(), Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL}); err != nil {
			t.Fatal(err)
		}
		k, err := ac.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{Instance: x.ref, JobId: job(), Ttl: durationpb.New(2160 * time.Hour)})
		if err != nil || !k.GetCreated() {
			t.Fatalf("BootstrapApiKey(%s): %v", x.ref.GetSlug(), err)
		}
		if r, err := ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: x.ref, JobId: job()}); err != nil || !r.GetAttached() {
			t.Fatalf("EnsureEdgeAttachment(%s): %v", x.ref.GetSlug(), err)
		}
		return k.GetPrefix()
	}
	keyA1 := up(ta)
	up(tb)

	// ---- tenant state before the backup: a member, a second user, three nodes (one with an approved route), a key
	member := uuid.NewString()
	memberUser := "mg-" + member
	for _, x := range []itTenant{ta, tb} {
		hs(x, "users", "create", memberUser, "-o", "json")
		hs(x, "users", "create", "bob", "-o", "json")
	}
	n1 := newNode(ta, memberUser, "n1")
	n2 := newNode(ta, "bob", "n2")
	n3 := newNode(ta, "bob", "n3", "10.9.0.0/24")
	hs(ta, "nodes", "approve-routes", "--identifier", strconv.FormatUint(n3.ID, 10), "--routes", "10.9.0.0/24", "-o", "json")
	newNode(tb, "bob", "b1")
	hs(ta, "preauthkeys", "create", "--user", "2", "--expiration", "24h", "-o", "json")

	// ---- B's state (AC-19 method: key hashes + normalised node/user/policy lists + StartedAt)
	stateOfB := func() string {
		t.Helper()
		files := dataFiles(t, tb.data())
		var l []hsNodeIT
		_ = json.Unmarshal(hs(tb, "nodes", "list", "-o", "json"), &l)
		for i := range l {
			l[i].Expiry = nil // not volatile, kept anyway below through the name
		}
		users := hs(tb, "users", "list", "-o", "json")
		pol := hs(tb, "policy", "get", "-o", "json")
		nl, _ := json.Marshal(l)
		return fmt.Sprintf("noise=%s derp=%s nodes=%s users=%s policy=%s started=%s", sha256Hex(files["noise_private.key"]),
			sha256Hex(files["derp_server_private.key"]), sha256Hex(nl), sha256Hex(users), sha256Hex(pol), statusOf(tb).GetStartedAt().AsTime())
	}
	bBefore := stateOfB()

	// ---- 1. online backup of A while A writes (V-12: VACUUM INTO on a read-only mount of a live WAL database)
	dataMeta := func(x itTenant) string {
		t.Helper()
		var parts []string
		entries, _ := os.ReadDir(x.data())
		for _, en := range entries {
			fi, _ := os.Lstat(filepath.Join(x.data(), en.Name()))
			st := fi.Sys().(*syscall.Stat_t)
			parts = append(parts, fmt.Sprintf("%s %d:%d %v", en.Name(), st.Uid, st.Gid, fi.Mode()))
		}
		sort.Strings(parts)
		return strings.Join(parts, "; ")
	}
	metaBefore := dataMeta(ta)
	backup := func(x itTenant, seq uint64, dk []byte) (*agentv1.BackupArtifact, error) {
		pub, _ := backupfmt.DataRecipient(dk)
		r, err := ac.Backup(ctx, &agentv1.BackupRequest{Instance: x.ref, JobId: job(), Sequence: seq, DataRecipient: pub})
		return r.GetArtifact(), err
	}
	rounds := 3
	if s := os.Getenv("MG_IT_V12_ROUNDS"); s != "" {
		rounds, _ = strconv.Atoi(s)
	}
	stopLoad := make(chan struct{})
	var load sync.WaitGroup
	load.Add(1)
	go func() { // write load: nodes registered and expired continuously in A while the backups run
		defer load.Done()
		for i := 0; ; i++ {
			select {
			case <-stopLoad:
				return
			default:
			}
			var b [12]byte
			_, _ = rand.Read(b[:])
			id := "hskey-authreq-" + hex.EncodeToString(b[:])
			_, _ = eng.Exec(ctx, "mg-hs-"+ta.ref.GetSlug(), []string{"headscale", "debug", "create-node", "--user", "bob", "--name", fmt.Sprintf("load%d", i), "--key", id}, 30*time.Second)
			_, _ = eng.Exec(ctx, "mg-hs-"+ta.ref.GetSlug(), []string{"headscale", "auth", "register", "--auth-id", id, "--user", "bob"}, 30*time.Second)
		}
	}()
	var v12 []time.Duration
	var loadArt *agentv1.BackupArtifact // the last backup taken under write load — restored at the end (V-12)
	var loadDK []byte
	for i := range rounds {
		dk, _ := backupfmt.NewDataKey()
		start := time.Now()
		art, err := backup(ta, uint64(1000+i), dk) //nolint:gosec // G115: test
		if err != nil {
			close(stopLoad)
			load.Wait()
			t.Fatalf("online backup %d under write load: %v", i, err)
		}
		v12 = append(v12, time.Since(start))
		loadArt, loadDK = art, dk
		if art.GetMethod() != agentv1.BackupMethod_BACKUP_METHOD_VACUUM_INTO {
			t.Fatalf("backup of a running instance: method %s", art.GetMethod())
		}
	}
	close(stopLoad)
	load.Wait()
	if after := dataMeta(ta); after != metaBefore {
		t.Fatalf("V-12: owner/mode of data/ changed by the online backups:\n%s\n%s", metaBefore, after)
	}
	t.Logf("V-12: %d online backups (VACUUM INTO, data/ read-only) under write load: %v; data/ owner/mode unchanged (%s)", rounds, v12, metaBefore)
	// the nodes created by the load are removed again (deleted before the backup that the restore uses)
	for name, n := range nodes(ta) {
		if strings.HasPrefix(name, "load") {
			hs(ta, "nodes", "delete", "--identifier", strconv.FormatUint(n.ID, 10), "--force")
		}
	}
	dkA, _ := backupfmt.NewDataKey()
	artA, err := backup(ta, 2000, dkA)
	if err != nil {
		t.Fatal(err)
	}
	m, err := backupfmt.Parse(artA.GetManifest(), artA.GetManifestSignature(), verifyKeys)
	if err != nil {
		t.Fatalf("the manifest of A does not verify: %v", err)
	}
	t.Logf("backup A: sequence %d, %d bytes, archive %s, manifest %s, sqlite %s, headscale %s", artA.GetSequence(), artA.GetSizeBytes(),
		artA.GetArchiveSha256()[:12], artA.GetManifestSha256()[:12], m.SQLiteVersion, m.HeadscaleVersion)
	archiveA := filepath.Join(a.cfg.Host.BackupsDir, ta.ref.GetInstanceId(), backupfmt.ArchiveName(2000))

	// ---- 2. DR path: the offline recovery identity decrypts the archive with the age binary; it holds no byte of B
	decrypt := func(identity string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, compose.AgeBinary, "-d", "-i", identity, archiveA) //nolint:gosec // G204: test
		var errb bytes.Buffer
		cmd.Stderr = &errb
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
		}
		return out, nil
	}
	plain, err := decrypt(idFile)
	if err != nil {
		t.Fatalf("DR path: %v", err)
	}
	var names []string
	tr := tar.NewReader(bytes.NewReader(plain))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	if !slices.Equal(names, backupfmt.ArchivePaths) {
		t.Fatalf("archive entries %v", names)
	}
	bFiles := dataFiles(t, tb.data())
	for _, f := range []string{"noise_private.key", "derp_server_private.key"} {
		if bytes.Contains(plain, bFiles[f]) || bytes.Contains(plain, bytes.TrimSpace(bFiles[f])[8:]) {
			t.Fatalf("A's archive contains B's %s", f)
		}
	}
	// B's data key (written as an identity file) does not open A's archive (T-15)
	dkB, _ := backupfmt.NewDataKey()
	idB, _ := backupfmt.AgeIdentity(dkB)
	idBFile := filepath.Join(e.root, "identity_b")
	write(t, idBFile, idB+"\n", 0o400)
	defer func() { _ = os.Remove(idBFile) }()
	if _, err := decrypt(idBFile); err == nil || !strings.Contains(err.Error(), "no identity matched") {
		t.Fatalf("B's data key opened A's archive: %v", err)
	}
	t.Logf("DR path: the recovery identity decrypts A's archive (%d tar bytes, %v); B's data key does not; no byte of B's keys inside", len(plain), names)

	// ---- 3. after the backup: API key rotated, n2 revoked, n3's route unapproved, member offboarded, n4 registered
	if _, err := ac.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{Instance: ta.ref, JobId: job(), Ttl: durationpb.New(2160 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	hs(ta, "nodes", "expire", "--identifier", strconv.FormatUint(n2.ID, 10), "-o", "json")
	hs(ta, "nodes", "approve-routes", "--identifier", strconv.FormatUint(n3.ID, 10), "--routes", "", "-o", "json")
	n4 := newNode(ta, "bob", "n4")
	var late hsUserIT
	if err := json.Unmarshal(hs(ta, "users", "create", "late", "-o", "json"), &late); err != nil || late.ID == 0 {
		t.Fatalf("user created after the backup: %v", err)
	}
	applied := []byte("{\n  \"grants\": [],\n  \"ssh\": []\n}") // the tightened policy applied after the backup

	// ---- 4. T-15: refusals BEFORE anything is decrypted
	restoreReq := func(x itTenant, art *agentv1.BackupArtifact, dk []byte) *agentv1.RestoreRequest {
		return &agentv1.RestoreRequest{Instance: x.ref, JobId: job(), DataKey: dk,
			Artifact: &agentv1.ArtifactRef{Sequence: art.GetSequence(), ArchiveSha256: art.GetArchiveSha256(), ManifestSha256: art.GetManifestSha256()},
			Policy:   &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: applied}}
	}
	restoreHelpers := func() int { return strings.Count(a.logs.String(), `"msg":"restore_swapped"`) }
	aFiles := dataFiles(t, ta.data())
	// A's archive placed in B's backup directory (an operator mistake, or an attacker with the backup volume)
	bdir := filepath.Join(a.cfg.Host.BackupsDir, tb.ref.GetInstanceId())
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{backupfmt.ArchiveName(2000), backupfmt.ManifestName(2000), backupfmt.SignatureName(2000)} {
		raw, err := os.ReadFile(filepath.Join(a.cfg.Host.BackupsDir, ta.ref.GetInstanceId(), n)) //nolint:gosec // G304: the test host
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(bdir, n), string(raw), 0o440)
	}
	_, err = ac.Restore(ctx, restoreReq(tb, artA, dkA))
	refusedAs("A's archive restored into B", err, agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH)
	// B's data key on A's archive: the helper cannot decrypt (real age)
	_, err = ac.Restore(ctx, restoreReq(ta, artA, dkB))
	refusedAs("A's archive with B's data key", err, agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY)
	// a changed manifest, then a manifest signed by another key
	mpath := filepath.Join(a.cfg.Host.BackupsDir, ta.ref.GetInstanceId(), backupfmt.ManifestName(2000))
	spath := filepath.Join(a.cfg.Host.BackupsDir, ta.ref.GetInstanceId(), backupfmt.SignatureName(2000))
	origM, _ := os.ReadFile(mpath) //nolint:gosec // G304: the test host
	origS, _ := os.ReadFile(spath) //nolint:gosec // G304: the test host
	write(t, mpath, string(bytes.Replace(origM, []byte(ta.ref.GetTenantId()), []byte(tb.ref.GetTenantId()), 1)), 0o400)
	_, err = ac.Restore(ctx, restoreReq(ta, artA, dkA))
	refusedAs("changed manifest", err, agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY)
	write(t, mpath, string(origM), 0o400)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	write(t, spath, string(backupfmt.Sign(other, origM)), 0o400)
	_, err = ac.Restore(ctx, restoreReq(ta, artA, dkA))
	refusedAs("manifest signed by another key", err, agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY)
	write(t, spath, string(origS), 0o400)
	if n := restoreHelpers(); n != 0 {
		t.Fatalf("%d restore swaps after refusals", n)
	}
	if !bytes.Equal(dataFiles(t, ta.data())["noise_private.key"], aFiles["noise_private.key"]) || statusOf(ta).GetEdgeAttachFlag() != true {
		t.Fatal("a refused restore changed A")
	}
	if got := stateOfB(); got != bBefore {
		t.Fatalf("AC-19: a refused restore changed B:\n%s\n%s", bBefore, got)
	}

	// ---- 5. the restore of A (§17.2 steps 2–4): applied policy offline, edge detached, data/ swapped, started
	res, err := ac.Restore(ctx, restoreReq(ta, artA, dkA))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	st := statusOf(ta)
	if st.GetEdgeAttachFlag() || st.GetNetwork().GetEdgeAttached() || st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING {
		t.Fatalf("after the restore: edge flag %v attached %v state %s", st.GetEdgeAttachFlag(), st.GetNetwork().GetEdgeAttached(), st.GetContainerState())
	}
	if res.GetPolicySha256() != sha256Hex(applied) {
		t.Fatalf("the restored instance serves policy %s, not the applied one", res.GetPolicySha256())
	}
	if _, err := os.Stat(filepath.Join(ta.dir, res.GetPreviousDataKeptAs(), "db.sqlite")); err != nil {
		t.Fatalf("previous data/ not kept: %v", err)
	}
	if got := strings.TrimSuffix(string(hs(ta, "policy", "get", "-o", "json")), "\n"); got != string(applied) {
		t.Fatalf("policy get: %q", got)
	}
	// before the reconcile the archive's state is back: the old API key valid, n4 gone
	if _, ok := nodes(ta)["n4"]; ok {
		t.Fatal("a node registered after the backup survived the restore")
	}

	// ---- 6. PostRestoreReconcile (§17.2 step 5) — still without the edge
	pr, err := ac.PostRestoreReconcile(ctx, &agentv1.PostRestoreReconcileRequest{Instance: ta.ref, JobId: job(), Plan: &agentv1.ReconcilePlan{
		ApiKeyTtl: durationpb.New(2160 * time.Hour), RevokedMachineKeys: []string{n2.MachineKey},
		Nodes:           []*agentv1.NodeDesiredState{{MachineKey: n3.MachineKey}, {MachineKey: n1.MachineKey}, {MachineKey: n4.MachineKey}},
		OffboardedUsers: []string{memberUser}}})
	if err != nil {
		t.Fatalf("PostRestoreReconcile: %v", err)
	}
	newKey := pr.GetApiKey()
	if newKey == "" || strings.Contains(a.logs.String(), newKey) {
		t.Fatal("no new API key, or the key is in the agent's log")
	}
	if pr.GetPreauthKeysExpired() < 1 || pr.GetNodesExpired() != 2 || pr.GetRoutesReset() != 1 || pr.GetApiKeysExpired() < 1 ||
		!slices.Equal(pr.GetUnmatchedMachineKeys(), []string{n4.MachineKey}) {
		t.Fatalf("reconcile report: preauth %d nodes %d routes %d apikeys %d unmatched %v", pr.GetPreauthKeysExpired(), pr.GetNodesExpired(),
			pr.GetRoutesReset(), pr.GetApiKeysExpired(), pr.GetUnmatchedMachineKeys())
	}
	// IT-16 at the moment the hostname would first answer: only the new API key is valid (the archive's key — the one
	// valid at backup time — is dead), every pre-auth key of the archive expired, the revoked node and the offboarded
	// member's node expired, the route not approved, the applied policy served
	var valid []string
	for _, k := range apiKeys(ta) {
		if k.valid() {
			valid = append(valid, k.Prefix)
		}
	}
	if len(valid) != 1 || !strings.Contains(valid[0], pr.GetApiKeyPrefix()) || strings.Contains(valid[0], keyA1) {
		t.Fatalf("valid API keys after the restore: %v (old %s, new %s)", valid, keyA1, pr.GetApiKeyPrefix())
	}
	for _, k := range preAuthKeys(ta) {
		if k.valid() {
			t.Fatalf("pre-auth key %d of the archive still valid", k.ID)
		}
	}
	after := nodes(ta)
	if !after["n2"].expired() || !after["n1"].expired() || after["n3"].expired() || len(after["n3"].ApprovedRoutes) != 0 {
		t.Fatalf("nodes after the reconcile: n1 expired %v, n2 expired %v, n3 expired %v routes %v", after["n1"].expired(), after["n2"].expired(),
			after["n3"].expired(), after["n3"].ApprovedRoutes)
	}
	// numeric ids handed out again (P2-T13): the restored id counters give a node and a user created after the restore
	// the ids of the ones created after the backup (gone) — the platform matches nodes by machine key (inventory.sync)
	// and members by name (re-resolution of §17.2 step 6), never by these ids. A pre-auth key issued for the stale id
	// lands on the newcomer; the one issued for the id resolved by name belongs to the right user.
	n5 := newNode(ta, "bob", "n5")
	var fresh hsUserIT
	if err := json.Unmarshal(hs(ta, "users", "create", "fresh", "-o", "json"), &fresh); err != nil {
		t.Fatal(err)
	}
	var users []hsUserIT
	if err := json.Unmarshal(hs(ta, "users", "list", "-o", "json"), &users); err != nil {
		t.Fatal(err)
	}
	byName := map[string]uint64{}
	for _, u := range users {
		byName[u.Name] = u.ID
	}
	if _, ok := byName["late"]; ok {
		t.Fatal("a user created after the backup survived the restore")
	}
	keyOwner := func(uid uint64) string {
		t.Helper()
		var k struct {
			User *hsUserIT `json:"user"`
		}
		if err := json.Unmarshal(hs(ta, "preauthkeys", "create", "--user", strconv.FormatUint(uid, 10), "--expiration", "15m", "-o", "json"), &k); err != nil || k.User == nil {
			t.Fatalf("pre-auth key for user %d: %v", uid, err)
		}
		return k.User.Name
	}
	staleOwner, rightOwner := keyOwner(late.ID), keyOwner(byName["bob"])
	if n5.ID != n4.ID || n5.MachineKey == n4.MachineKey || fresh.ID != late.ID || staleOwner != "fresh" || rightOwner != "bob" {
		t.Fatalf("ids after the restore: n5 %d (n4 %d), fresh %d (late %d), key for the stale id → %q, by name → %q", n5.ID, n4.ID,
			fresh.ID, late.ID, staleOwner, rightOwner)
	}
	t.Logf("ids after the restore: node n5 got id %d — n4's (registered after the backup, gone), another machine key; user fresh got id %d — late's; a pre-auth key for the stale id belongs to %q, for the id resolved by name to %q",
		n5.ID, fresh.ID, staleOwner, rightOwner)
	// the edge again (§17.2 step 6), on the same Noise key (V-11: the restore keeps the server identity)
	if r, err := ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: ta.ref, JobId: job()}); err != nil || !r.GetAttached() {
		t.Fatalf("re-attach after the reconcile: %v", err)
	}
	if fp := statusOf(ta).GetNoiseKeyFingerprint(); fp != m.NoiseFingerprint {
		t.Fatalf("Noise key after the restore: %s, archive %s", fp, m.NoiseFingerprint)
	}
	if got := stateOfB(); got != bBefore {
		t.Fatalf("AC-19: restoring A changed B:\n%s\n%s", bBefore, got)
	}
	for _, msg := range []string{"backup_created", "restore_swapped", "restore_started", "post_restore_reconciled"} {
		for _, l := range a.logs.lines(t, msg) {
			if l["instance_id"] == tb.ref.GetInstanceId() {
				t.Fatalf("AC-19: an operation of A logged B's instance: %v", l)
			}
		}
	}
	t.Logf("restore A: kept %s; reconcile: %d pre-auth keys, %d nodes expired, %d route reset, %d API keys expired; B unchanged",
		res.GetPreviousDataKeptAs(), pr.GetPreauthKeysExpired(), pr.GetNodesExpired(), pr.GetRoutesReset(), pr.GetApiKeysExpired())

	// ---- 7. cold copy: a backup of the stopped instance, then started again
	if _, err := ac.StopInstance(ctx, &agentv1.StopInstanceRequest{Instance: ta.ref, JobId: job()}); err != nil {
		t.Fatal(err)
	}
	dkC, _ := backupfmt.NewDataKey()
	cold, err := backup(ta, 3000, dkC)
	if err != nil || cold.GetMethod() != agentv1.BackupMethod_BACKUP_METHOD_COLD_COPY {
		t.Fatalf("cold backup: %v %s", err, cold.GetMethod())
	}

	// ---- 8. IT-15: a hostile data/ in A (instance stopped) — backup and start guard fail closed, nothing of B read
	good := dataFiles(t, ta.data())
	bKey := filepath.Join(tb.data(), "noise_private.key")
	restoreGood := func() { setData(t, ta.data(), good, ta.uid) }
	guardRefusals := func(reason string) int {
		n := 0
		for _, l := range a.logs.lines(t, "start_guard_failed") {
			if l["instance_id"] == ta.ref.GetInstanceId() && l["reason"] == reason {
				n++
			}
		}
		return n
	}
	hostile := []struct {
		name        string
		plant       func()
		backup      agentv1.RefusalReason
		guardReason string // "" when the start guard has nothing to say (an extra file it does not look at)
	}{
		{"symlink to B's Noise key as derp_server_private.key", func() {
			_ = os.Remove(filepath.Join(ta.data(), "derp_server_private.key"))
			_ = os.Symlink(bKey, filepath.Join(ta.data(), "derp_server_private.key"))
		}, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, "data_file_not_regular"},
		{"symlink to B's Noise key as db.sqlite-wal", func() {
			_ = os.Symlink(bKey, filepath.Join(ta.data(), "db.sqlite-wal"))
		}, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, ""},
		{"FIFO as noise_private.key", func() {
			_ = os.Remove(filepath.Join(ta.data(), "noise_private.key"))
			_ = syscall.Mkfifo(filepath.Join(ta.data(), "noise_private.key"), 0o600)
			_ = os.Chown(filepath.Join(ta.data(), "noise_private.key"), ta.uid, ta.uid)
		}, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, "data_file_not_regular"},
		{"huge sparse db.sqlite", func() {
			f, _ := os.OpenFile(filepath.Join(ta.data(), "db.sqlite"), os.O_WRONLY, 0)
			_ = f.Truncate(1 << 40)
			_ = f.Close()
		}, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, "data_file_oversized"},
		{"corrupt database", func() {
			_ = os.WriteFile(filepath.Join(ta.data(), "db.sqlite"), bytes.Repeat([]byte{0xa5}, 8192), 0o600)
		}, agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY, "database_invalid"},
	}
	for i, c := range hostile {
		c.plant()
		start := time.Now()
		dk, _ := backupfmt.NewDataKey()
		seq := uint64(4000 + i) //nolint:gosec // G115: test
		_, err := backup(ta, seq, dk)
		refusedAs("IT-15 backup: "+c.name, err, c.backup)
		if d := time.Since(start); d > 60*time.Second {
			t.Fatalf("IT-15 %s: the backup took %v (a FIFO must not block)", c.name, d)
		}
		if _, err := os.Lstat(filepath.Join(a.cfg.Host.BackupsDir, ta.ref.GetInstanceId(), backupfmt.ArchiveName(seq))); err == nil {
			t.Fatalf("IT-15 %s: an archive was written", c.name)
		}
		if c.guardReason != "" {
			nBefore := guardRefusals(c.guardReason)
			_, err := ac.StartInstance(ctx, &agentv1.StartInstanceRequest{Instance: ta.ref, JobId: job()})
			if status.Code(err) != codes.FailedPrecondition || guardRefusals(c.guardReason) != nBefore+1 {
				t.Fatalf("IT-15 start guard %s: %v (events %d)", c.name, err, guardRefusals(c.guardReason))
			}
		}
		// the agent keeps answering for the other instance
		if statusOf(tb).GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING {
			t.Fatal("B is not running")
		}
		restoreGood()
	}
	if n := len(a.logs.lines(t, "security_event")); n < len(hostile) {
		t.Fatalf("IT-15: %d security events for %d hostile data directories", n, len(hostile))
	}
	dkB2, _ := backupfmt.NewDataKey()
	if _, err := backup(tb, 1, dkB2); err != nil {
		t.Fatalf("the agent no longer serves B: %v", err)
	}
	// A starts again on its own (good) data
	if _, err := ac.StartInstance(ctx, &agentv1.StartInstanceRequest{Instance: ta.ref, JobId: job()}); err != nil {
		t.Fatalf("A on its own data: %v", err)
	}
	if got := stateOfB(); got != bBefore {
		t.Fatalf("AC-19: B changed during IT-15:\n%s\n%s", bBefore, got)
	}
	t.Logf("IT-15: %d hostile data directories refused by the backup (security events) and the start guard; B served throughout", len(hostile))

	// ---- 9. V-12: the backup taken under write load (the last online round) is restored — Headscale comes up healthy
	// on it (the restore waits for it), serving the applied policy, with the nodes the load had registered by then
	waitHealthy(ta)
	rl, err := ac.Restore(ctx, restoreReq(ta, loadArt, loadDK))
	if err != nil {
		t.Fatalf("V-12: restore of the backup taken under write load: %v", err)
	}
	waitHealthy(ta)
	loadNodes := 0
	for name := range nodes(ta) {
		if strings.HasPrefix(name, "load") {
			loadNodes++
		}
	}
	if rl.GetPolicySha256() != sha256Hex(applied) {
		t.Fatalf("V-12: the restored instance serves policy %s", rl.GetPolicySha256())
	}
	if got := stateOfB(); got != bBefore {
		t.Fatalf("AC-19: restoring A again changed B:\n%s\n%s", bBefore, got)
	}
	t.Logf("V-12: the backup taken under write load (sequence %d) restored: healthy, applied policy served, %d nodes of the load in it",
		loadArt.GetSequence(), loadNodes)

	// ---- clean up: no helper left, nothing outside the test's objects changed
	for _, x := range []itTenant{ta, tb} {
		_, _ = ac.RemoveEdgeAttachment(ctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: x.ref, JobId: job(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION})
		if _, err := ac.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: x.ref, JobId: job(), Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP}); err != nil {
			t.Fatalf("remove %s: %v", x.ref.GetSlug(), err)
		}
	}
	cl, err := dc.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cl.Items {
		if strings.HasPrefix(strings.TrimPrefix(c.Names[0], "/"), "mg-helper-"+e.prefix+"-") {
			t.Fatalf("helper container left: %s", c.Names[0])
		}
	}
	_, _ = dc.ContainerRemove(ctx, edgeName, client.ContainerRemoveOptions{Force: true})
	_, _ = dc.NetworkRemove(ctx, enr.ID, client.NetworkRemoveOptions{})
	for _, x := range []itTenant{ta, tb} {
		_ = os.RemoveAll(x.dir)
		_ = os.RemoveAll(filepath.Join(a.cfg.Host.BackupsDir, x.ref.GetInstanceId()))
	}
	for _, d := range diff(before, observe(t, dc, e.root)) {
		if strings.Contains(d, e.prefix) && !strings.HasPrefix(d, "+ path ") {
			t.Errorf("left behind or changed: %s", d)
		}
	}
}
