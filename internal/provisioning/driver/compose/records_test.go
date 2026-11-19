//go:build linux

package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// TestRenderRecords: sorted (name, type, value), Headscale's keys, "[]\n" when empty, deterministic.
func TestRenderRecords(t *testing.T) {
	if got, _ := RenderRecords(nil); string(got) != "[]\n" {
		t.Fatalf("empty = %q", got)
	}
	recs := []agentspec.DNSRecord{
		{Name: "web.acme.example", Type: "AAAA", Value: netip.MustParseAddr("fd7a:115c:a1e0::5")},
		{Name: "db.acme.example", Type: "A", Value: netip.MustParseAddr("100.64.0.9")},
		{Name: "web.acme.example", Type: "A", Value: netip.MustParseAddr("100.64.0.5")},
	}
	a, err := RenderRecords(recs)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RenderRecords([]agentspec.DNSRecord{recs[2], recs[0], recs[1]})
	if string(a) != string(b) {
		t.Fatal("not deterministic")
	}
	var got []map[string]string
	if err := json.Unmarshal(a, &got); err != nil || len(got) != 3 {
		t.Fatalf("%s: %v", a, err)
	}
	if got[0]["name"] != "db.acme.example" || got[1]["type"] != "A" || got[2]["value"] != "fd7a:115c:a1e0::5" {
		t.Fatalf("order/keys: %s", a)
	}
	if a[len(a)-1] != '\n' {
		t.Fatal("no trailing newline")
	}
}

func recordsInode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// TestWriteDNSRecords: the file is replaced atomically (a new inode — tmp + rename in records/), root:run_gid 0440, the
// answer is the sha256 of the content; the same records again change nothing; no record writes "[]"; an instance
// without its directory is refused.
func TestWriteDNSRecords(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	file := filepath.Join(rg.idir, "records", "extra-records.json")
	before := recordsInode(t, file)
	recs := []agentspec.DNSRecord{{Name: "db.acme.example", Type: "A", Value: netip.MustParseAddr("100.64.0.9")}}
	resp, err := rg.d.WriteDNSRecords(ctx, agentspec.DNSRecords{Call: rg.call(), Records: recs})
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(file) //nolint:gosec // G304: the instance file under t.TempDir()
	want, _ := RenderRecords(recs)
	sum := sha256.Sum256(want)
	if string(content) != string(want) || resp.GetRecordsSha256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("file %q sha %s", content, resp.GetRecordsSha256())
	}
	after := recordsInode(t, file)
	if after == before {
		t.Fatal("written in place: Headscale's watcher on the directory needs a rename (OPS-17)")
	}
	uid, gid, mode := ownerMode(t, file)
	if uid != os.Geteuid() || gid != int(rg.s.RunUID) || mode != 0o440 {
		t.Fatalf("owner %d:%d mode %v", uid, gid, mode)
	}
	entries, _ := os.ReadDir(filepath.Join(rg.idir, "records"))
	if len(entries) != 1 {
		t.Fatalf("records/ holds %d entries (a temporary file left)", len(entries))
	}
	// the same records: nothing written
	if _, err := rg.d.WriteDNSRecords(ctx, agentspec.DNSRecords{Call: rg.call(), Records: recs}); err != nil || recordsInode(t, file) != after {
		t.Fatalf("same content rewritten: %v", err)
	}
	// no record: []
	if _, err := rg.d.WriteDNSRecords(ctx, agentspec.DNSRecords{Call: rg.call()}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(file); string(got) != "[]\n" { //nolint:gosec // G304: under t.TempDir()
		t.Fatalf("empty set wrote %q", got)
	}
	// an instance without its directory
	other := agentspec.Call{Ref: agentspec.Ref{InstanceID: uuid.New(), TenantID: rg.s.Ref.TenantID, Slug: "other"}, JobID: uuid.New()}
	if _, err := rg.d.WriteDNSRecords(ctx, agentspec.DNSRecords{Call: other}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND {
		t.Fatalf("unknown instance: %v", err)
	}
}
