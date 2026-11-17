package jobs

// Idempotency-Key of the API (§13.1, table idempotency_keys — §6.3): mandatory on POST that create a resource or a job.
// The key is stored per (tenant, identity, operationId, key) with the SHA-256 of the request; the API middleware calls
// BeginIdempotent in its own short transaction (committed before the operation runs, so a concurrent duplicate sees
// in_progress) and CompleteIdempotent / FailIdempotent when the operation ends — ideally in the transaction of the
// business change. retention.sweep deletes keys 24 hours after they were taken.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// IdempotencyTTL is how long a key and its stored response are kept (§6.4: 24 hours).
const IdempotencyTTL = 24 * time.Hour

// IdempotencyKey names one use of an Idempotency-Key.
type IdempotencyKey struct {
	TenantID    *uuid.UUID // nil on platform routes
	IdentityID  uuid.UUID
	OperationID string // operationId of api/openapi.yaml
	Key         string
}

// IdempotencyOutcome tells the API what to do with a request carrying an Idempotency-Key.
type IdempotencyOutcome int

const (
	// IdempotencyProceed: first use of the key (or a retry after a failure, a crash or the key's expiry) — run the
	// operation, then CompleteIdempotent or FailIdempotent.
	IdempotencyProceed IdempotencyOutcome = iota
	// IdempotencyReplay: the same request completed before — return the stored response.
	IdempotencyReplay
	// IdempotencyInProgress: the same request is still running — 409 + Retry-After.
	IdempotencyInProgress
	// IdempotencyKeyReuse: the key was used for another request — 422 idempotency_key_reuse.
	IdempotencyKeyReuse
)

// StoredResponse is what a completed request stored for replay. The body never holds a secret: a show-once secret is
// referenced by SecretRef (TTL in the SecretStore — §13.1).
type StoredResponse struct {
	Status    int
	Body      json.RawMessage
	SecretRef *string
	Resource  *Resource
}

// IdempotencyDecision is the result of BeginIdempotent.
type IdempotencyDecision struct {
	Outcome    IdempotencyOutcome
	Response   *StoredResponse // IdempotencyReplay
	RetryAfter time.Duration   // IdempotencyInProgress
}

var (
	// ErrInvalidIdempotencyKey: an empty or oversized key, operation or identity, or a request hash that is not SHA-256.
	ErrInvalidIdempotencyKey = errors.New("jobs: invalid idempotency key")
	// ErrIdempotencyLost: the key is no longer held by this request (it expired and another request took it over).
	ErrIdempotencyLost = errors.New("jobs: idempotency key no longer held by this request")
)

// RequestHash is SHA-256 over the method, the normalised path (with {tenantId}) and the body re-encoded as canonical
// JSON — object keys sorted, insignificant whitespace dropped — so formatting differences are the same request.
func RequestHash(method, path string, body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(strings.ToUpper(method) + "\n" + path + "\n"))
	h.Write(canonicalJSON(body))
	return h.Sum(nil)
}

func canonicalJSON(b []byte) []byte {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return b
	}
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return out
}

func (k IdempotencyKey) check(hash []byte) error {
	if k.IdentityID == uuid.Nil || k.OperationID == "" || len(k.OperationID) > 128 || k.Key == "" || len(k.Key) > 255 ||
		len(hash) != sha256.Size {
		return ErrInvalidIdempotencyKey
	}
	return nil
}

// BeginIdempotent takes the key for the request with this hash, in q's transaction. lockFor bounds how long the request
// holds the key while in progress: past it, a crashed request no longer blocks a retry.
func BeginIdempotent(ctx context.Context, q *sqlcdb.Queries, k IdempotencyKey, hash []byte, lockFor time.Duration) (IdempotencyDecision, error) {
	if err := k.check(hash); err != nil {
		return IdempotencyDecision{}, err
	}
	if lockFor <= 0 {
		return IdempotencyDecision{}, errorf("lockFor must be > 0")
	}
	for range 3 {
		_, err := q.InsertIdempotencyKey(ctx, sqlcdb.InsertIdempotencyKeyParams{TenantID: k.TenantID, IdentityID: k.IdentityID,
			OperationID: k.OperationID, Key: k.Key, RequestHash: hash, LockSecs: lockFor.Seconds(), TtlSecs: IdempotencyTTL.Seconds()})
		if err == nil {
			return IdempotencyDecision{Outcome: IdempotencyProceed}, nil
		}
		if !errors.Is(err, store.ErrNoRows) {
			return IdempotencyDecision{}, err
		}
		cur, err := q.GetIdempotencyKeyForUpdate(ctx, sqlcdb.GetIdempotencyKeyForUpdateParams{TenantID: k.TenantID,
			IdentityID: k.IdentityID, OperationID: k.OperationID, Key: k.Key})
		if errors.Is(err, store.ErrNoRows) {
			continue // swept in between: insert again
		}
		if err != nil {
			return IdempotencyDecision{}, err
		}
		r := cur.IdempotencyKey
		switch {
		case cur.Expired:
			// past its 24 hours: a new request may use the key
		case !bytes.Equal(r.RequestHash, hash):
			return IdempotencyDecision{Outcome: IdempotencyKeyReuse}, nil
		case r.Status == "completed":
			return IdempotencyDecision{Outcome: IdempotencyReplay, Response: storedResponse(r)}, nil
		case r.Status == "in_progress" && cur.LockedForSecs > 0:
			return IdempotencyDecision{Outcome: IdempotencyInProgress,
				RetryAfter: time.Duration(math.Ceil(cur.LockedForSecs)) * time.Second}, nil
		}
		// expired, failed, or in progress past locked_until (crashed): take the key over
		if _, err := q.ClaimIdempotencyKey(ctx, sqlcdb.ClaimIdempotencyKeyParams{RequestHash: hash, LockSecs: lockFor.Seconds(),
			TtlSecs: IdempotencyTTL.Seconds(), TenantID: k.TenantID, IdentityID: k.IdentityID, OperationID: k.OperationID,
			Key: k.Key}); err != nil {
			return IdempotencyDecision{}, err
		}
		return IdempotencyDecision{Outcome: IdempotencyProceed}, nil
	}
	return IdempotencyDecision{}, errorf("idempotency key of %s: concurrent changes", k.OperationID)
}

// CompleteIdempotent stores the response of the request holding the key, for replay.
func CompleteIdempotent(ctx context.Context, q *sqlcdb.Queries, k IdempotencyKey, hash []byte, resp StoredResponse) error {
	if err := k.check(hash); err != nil {
		return err
	}
	if resp.Status < 100 || resp.Status > 599 {
		return errorf("invalid response status %d", resp.Status)
	}
	status := int32(resp.Status) //nolint:gosec // 100–599
	p := sqlcdb.FinishIdempotencyKeyParams{Status: "completed", ResponseStatus: &status, ResponseBody: resp.Body,
		SecretRef: resp.SecretRef, TenantID: k.TenantID, IdentityID: k.IdentityID, OperationID: k.OperationID, Key: k.Key,
		RequestHash: hash}
	if len(p.ResponseBody) == 0 {
		p.ResponseBody = nil
	}
	if resp.Resource != nil {
		p.ResourceType, p.ResourceID = &resp.Resource.Type, &resp.Resource.ID
	}
	return finishIdempotent(ctx, q, p)
}

// FailIdempotent releases the key after a failed request, so the client may retry with the same key.
func FailIdempotent(ctx context.Context, q *sqlcdb.Queries, k IdempotencyKey, hash []byte) error {
	if err := k.check(hash); err != nil {
		return err
	}
	return finishIdempotent(ctx, q, sqlcdb.FinishIdempotencyKeyParams{Status: "failed", TenantID: k.TenantID,
		IdentityID: k.IdentityID, OperationID: k.OperationID, Key: k.Key, RequestHash: hash})
}

func finishIdempotent(ctx context.Context, q *sqlcdb.Queries, p sqlcdb.FinishIdempotencyKeyParams) error {
	_, err := q.FinishIdempotencyKey(ctx, p)
	if errors.Is(err, store.ErrNoRows) {
		return ErrIdempotencyLost
	}
	return err
}

func storedResponse(r sqlcdb.IdempotencyKey) *StoredResponse {
	out := &StoredResponse{Body: r.ResponseBody, SecretRef: r.SecretRef}
	if r.ResponseStatus != nil {
		out.Status = int(*r.ResponseStatus)
	}
	if r.ResourceType != nil && r.ResourceID != nil {
		out.Resource = &Resource{Type: *r.ResourceType, ID: *r.ResourceID}
	}
	return out
}
