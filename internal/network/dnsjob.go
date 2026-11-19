package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// The dns.records_write job (worker): level-triggered — its input names nothing; it reads the tenant's whole record set
// when it runs and has the Host Agent write records/extra-records.json atomically (tmp + rename in the directory the
// Headscale container mounts read-only; [] when empty — Headscale watches the file: no restart, RT-04). A change
// committed while the job runs finds it unfinished and is not enqueued again (dedupe): the job reads the set again
// after writing and writes once more when it changed (at most maxRecordRounds). Headscale has no API that tells whether
// it loaded the file (HS-13): the job's evidence is the agent's sha256 of what it wrote, recorded in the job's output
// and in the audit event dns.records.write (actor system).

// ActionDNSRecordsWrite is the audit event of a write of the records file (actor system).
const ActionDNSRecordsWrite = "dns.records.write"

const maxRecordRounds = 3

// InstanceRef names the instance the Host Agent writes for (agentv1.InstanceRef).
type InstanceRef struct {
	InstanceID, TenantID uuid.UUID
	Slug                 string
}

// RecordsWriter writes the records file of an instance (Host Agent WriteDnsRecords — wired in apps/ over the agent
// client; network may not import provisioning or the agent client, §13.6). It returns the sha256 of the file written;
// an error the agent may lift by itself is a jobs.Transient, anything else a jobs.Permanent.
type RecordsWriter interface {
	WriteRecords(ctx context.Context, ref InstanceRef, jobID uuid.UUID, records []DNSRecord) (string, error)
}

// RecordsJobOutput is the output of a dns.records_write job.
type RecordsJobOutput struct {
	Records       int    `json:"records"`
	SetSHA256     string `json:"set_sha256"`     // of the record set read from the database
	RecordsSHA256 string `json:"records_sha256"` // of the file the agent wrote
	Rounds        int    `json:"rounds"`
	Skipped       string `json:"skipped,omitempty"`
}

// RegisterRecordsJob registers the dns.records_write handler on the worker (apps/ wiring — jobs imports no business
// module).
func (s *Service) RegisterRecordsJob(w *jobs.Worker, writer RecordsWriter) error {
	if writer == nil {
		return errors.New("network: dns.records_write needs a records writer")
	}
	return w.Register(KindDNSRecordsWrite, jobs.HandlerFunc(func(ctx context.Context, run *jobs.Run) error {
		return s.runRecordsJob(ctx, run, writer)
	}))
}

// recordSet is the tenant's state the job writes.
type recordSet struct {
	ref     InstanceRef
	status  string
	records []DNSRecord
	sum     string
}

func setSHA(recs []DNSRecord) string {
	var b strings.Builder
	for _, r := range recs {
		b.WriteString(r.Name + "\t" + r.Type + "\t" + r.Value.String() + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func (s *Service) readRecordSet(ctx context.Context, tenantID uuid.UUID) (recordSet, error) {
	var out recordSet
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		inst, err := q.GetNetworkInstance(ctx, tenantID)
		if err != nil {
			return err
		}
		out.ref = InstanceRef{InstanceID: inst.InstanceID, TenantID: tenantID, Slug: inst.Slug}
		out.status = inst.InstanceStatus
		rows, err := q.ListDNSRecords(ctx, tenantID)
		if err != nil {
			return err
		}
		out.records = make([]DNSRecord, 0, len(rows))
		for _, r := range rows {
			out.records = append(out.records, recordOf(r))
		}
		out.sum = setSHA(out.records)
		return nil
	})
	return out, err
}

func (s *Service) runRecordsJob(ctx context.Context, run *jobs.Run, writer RecordsWriter) error {
	if run.TenantID == nil {
		return jobs.Permanent("invalid_input", errors.New("dns.records_write needs a tenant"))
	}
	tenantID := *run.TenantID
	out := RecordsJobOutput{}
	for round := 1; round <= maxRecordRounds; round++ {
		set, err := s.readRecordSet(ctx, tenantID)
		switch {
		case errors.Is(err, store.ErrNoRows):
			out.Skipped = "no_instance" // deprovisioned: nothing to write to
			return run.SetOutput(out)
		case err != nil:
			return jobs.Transient("store", fmt.Errorf("read the records: sqlstate %q", store.SQLState(err)))
		}
		switch set.status {
		case "running":
		case "quarantined", "removed":
			out.Skipped = "instance_" + set.status // never written to an isolated instance; the next change writes again
			return run.SetOutput(out)
		default:
			return jobs.Transient("instance_not_running", fmt.Errorf("instance %s is %s", set.ref.InstanceID, set.status))
		}
		sum, err := writer.WriteRecords(ctx, set.ref, run.ID, set.records)
		if err != nil {
			var je *jobs.Error
			if errors.As(err, &je) {
				return err
			}
			return jobs.Transient("agent", err)
		}
		out.Records, out.SetSHA256, out.RecordsSHA256, out.Rounds = len(set.records), set.sum, sum, round
		if err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
			t := tenantID
			return audit.Record(ctx, q, audit.Event{Action: ActionDNSRecordsWrite, TenantID: &t, ActorType: audit.ActorSystem,
				ActorDisplay: KindDNSRecordsWrite, ResourceType: "dns_records", ResourceID: tenantID.String(),
				Details: audit.Details{"job_id": run.ID, "records": len(set.records), "set_sha256": set.sum,
					"records_sha256": sum, "instance_id": set.ref.InstanceID}})
		}); err != nil {
			return jobs.Transient("store", fmt.Errorf("record the write: sqlstate %q", store.SQLState(err)))
		}
		again, err := s.readRecordSet(ctx, tenantID)
		if err != nil {
			return jobs.Transient("store", fmt.Errorf("read the records again: sqlstate %q", store.SQLState(err)))
		}
		if again.sum == set.sum {
			break
		}
	}
	return run.SetOutput(out)
}
