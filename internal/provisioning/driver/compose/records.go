package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Extra DNS records (P4-T12, §11.5 WriteDNSRecords, §14.2 records/, HS-FC-21, OPS-17). records/ is mounted read-only as
// a DIRECTORY into the Headscale container (/etc/headscale-records): the file is replaced with tmp + rename in that
// directory (a single-file bind mount would pin the old inode), Headscale watches it and reloads the records without a
// restart (RT-04). The file is never empty — no record is "[]" (an empty file is ignored by Headscale).

// RenderRecords is records/extra-records.json for validated records: a JSON array sorted by (name, type, value) — the
// keys of Headscale's extra_records ("name", "type", "value") —, two-space indented, one trailing newline; "[]\n" when
// there is none (InitialRecords).
func RenderRecords(recs []agentspec.DNSRecord) ([]byte, error) {
	type rec struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	out := make([]rec, 0, len(recs))
	for _, r := range recs {
		out = append(out, rec{Name: r.Name, Type: r.Type, Value: r.Value.String()})
	}
	slices.SortFunc(out, func(a, b rec) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		if c := strings.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		return strings.Compare(a.Value, b.Value)
	})
	if len(out) == 0 {
		return []byte(InitialRecords), nil
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// WriteDNSRecords — the agent side of the job dns.records_write: the instance must have its directory (meta) — the
// file is written with the owner and mode of the tenant's files (root:run_gid 0440), atomically; nothing is written when
// the content is already the same. The answer is the sha256 of the file's content.
func (d *Driver) WriteDNSRecords(_ context.Context, r agentspec.DNSRecords) (*agentv1.WriteDnsRecordsResponse, error) {
	l := newLayout(r.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, err := d.readState(t, l, r.Ref.InstanceID)
	if err != nil {
		return nil, err
	}
	content, err := RenderRecords(r.Records)
	if err != nil {
		return nil, err
	}
	changed, err := t.writeFile(l.recordsFile, content, t.owners(int(st.runUID))["tenant"])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	out := hex.EncodeToString(sum[:])
	d.cfg.Log.Info("instance_dns_records_written", "instance_id", l.id, "job_id", r.JobID.String(), "file",
		filepath.ToSlash(l.recordsFile), "records", len(r.Records), "changed", changed, "records_sha256", out)
	return &agentv1.WriteDnsRecordsResponse{RecordsSha256: out}, nil
}
