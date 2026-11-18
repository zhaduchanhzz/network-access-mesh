package devices

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// ActionTag is the audit action of PUT /devices/{id}/tags (paired: requested before SetTags, then succeeded/failed).
const ActionTag = "device.tag"

// TagCatalog checks tag names against the tenant's tag catalog (P4-T15 — policies.TagService.CheckTags, wired in apps/:
// devices may not import policies — §13.6). It returns the names sorted without duplicates; a refusal of the caller's
// input carries a Validation() (field, reason, tags, ok) method.
type TagCatalog interface {
	CheckTags(ctx context.Context, tenantID uuid.UUID, names []string, field string) ([]string, error)
}

// tagValidation is the input refusal of a TagCatalog.
type tagValidation interface {
	Validation() (field, reason string, tags []string, ok bool)
}

// catalogError maps an error of the catalog: the caller's input ⇒ 422 on the field (the names outside the catalog in
// the detail — they are the caller's own input); anything else is internal.
func catalogError(err error) error {
	var v tagValidation
	if errors.As(err, &v) {
		if field, reason, tags, ok := v.Validation(); ok {
			if field == "" {
				field = "tags"
			}
			detail := "tags must be a non-empty list of at most 64 names of the form tag:<lowercase name>"
			if len(tags) > 0 {
				detail = "these tags are not in the tenant's tag catalog: " + strings.Join(tags, ", ")
			}
			return &Error{Code: CodeValidationFailed, Reason: reason, Field: field, Detail: detail, Err: err}
		}
	}
	return &Error{Code: CodeInternal, Reason: "tag_catalog", Err: err}
}

// SetTags replaces the tags of a device (PUT /tenants/{t}/devices/{id}/tags — §13.2): the list must be non-empty and
// every name in the tenant's tag catalog (P4-T15 — refused before anything is written or called); If-Match must be the
// tags_etag of the tags Headscale holds NOW (read directly with GetNode just before the write — missing ⇒ 428, stale ⇒
// 412); device.tag.requested commits before Headscale is called, the node's identity (node id + machine key) is checked,
// SetTags replaces the whole set (Headscale also refuses a tag its current policy does not declare — the catalog is
// rendered into "tagOwners" by policy.apply), the read-back must hold exactly the new set, and the register and
// device.tag.succeeded commit together. A tagged node no longer belongs to a user (PL-09): the owner is cleared.
func (s *Service) SetTags(ctx context.Context, tenantID, deviceID uuid.UUID, a Access, ifMatch string, tags []string) (Device, error) {
	if s.tags == nil {
		return Device{}, &Error{Code: CodeInternal, Reason: ReasonNoTagCatalog, Err: errors.New("devices: no tag catalog wired")}
	}
	if len(tags) == 0 {
		return Device{}, &Error{Code: CodeValidationFailed, Reason: "tags_empty", Field: "tags",
			Detail: "tags must not be empty: Headscale cannot remove every tag of a node (V-28)"}
	}
	match := strings.TrimSpace(ifMatch)
	var (
		row  sqlcdb.DeviceInventoryCache
		op   audit.Operation
		norm []string
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		// the device first: another tenant's or a missing device is 404 whatever the request (§8.4 invariant 6)
		r, err := q.LockLiveDevice(ctx, sqlcdb.LockLiveDeviceParams{TenantID: tenantID, ID: deviceID})
		if errors.Is(err, store.ErrNoRows) {
			return notFound(ReasonNoDevice)
		}
		if err != nil {
			return err
		}
		if !a.owns(r) {
			return notFound(ReasonNotOwnResource)
		}
		if match == "" || match == "*" {
			return &Error{Code: CodePreconditionReq, Reason: "if_match_required",
				Detail: "If-Match with the device's tags_etag is required."}
		}
		if norm, err = s.tags.CheckTags(ctx, tenantID, tags, "tags"); err != nil {
			return catalogError(err)
		}
		row = r
		op, err = audit.Requested(ctx, q, audit.Event{Action: ActionTag, TenantID: &tenantID, ResourceType: resourceDevice,
			ResourceID: deviceID.String(), Details: audit.Details{"tags": norm, "previous": r.Tags, "node_id": r.HeadscaleNodeID}})
		return err
	})
	if err != nil {
		return Device{}, err
	}
	fail := func(err error) (Device, error) {
		e := fromAdapter(err)
		s.closeFailed(ctx, tenantID, &op, e.Reason)
		return Device{}, e
	}
	inst, err := s.reg.ForTenant(ctx, tenantID)
	if err != nil {
		return fail(err)
	}
	nodeID := uint64(row.HeadscaleNodeID) //nolint:gosec // CHECK headscale_node_id > 0
	node, err := inst.GetNode(ctx, nodeID)
	switch {
	case isGone(err) || err == nil && node.MachineKey != row.MachineKey:
		return fail(notFound(ReasonNodeGone))
	case err != nil:
		return fail(err)
	}
	if setETag(node.Tags) != match {
		return fail(&Error{Code: CodePreconditionFailed, Reason: ReasonStaleTags,
			Detail: "The device's tags changed since they were read; read the device again."})
	}
	tagged, err := inst.SetTags(ctx, nodeID, norm)
	if err != nil {
		e := fromAdapter(err)
		if e.Code == CodeValidationFailed {
			e.Field = "tags"
		}
		return fail(e)
	}
	got := slices.Clone(tagged.Tags)
	slices.Sort(got)
	if !slices.Equal(slices.Compact(got), norm) || tagged.MachineKey != row.MachineKey {
		return fail(&Error{Code: CodeUpstreamRejected, Reason: ReasonReadbackMismatch,
			Detail: "the tenant's control plane did not apply the new tags"})
	}
	var d Device
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		if err := q.SetDeviceTags(ctx, sqlcdb.SetDeviceTagsParams{Tags: norm, TenantID: tenantID, ID: deviceID}); err != nil {
			return err
		}
		if err := op.Succeeded(ctx, q, audit.Details{"tags": norm}); err != nil {
			return err
		}
		r, err := q.GetLiveDevice(ctx, sqlcdb.GetLiveDeviceParams{TenantID: tenantID, ID: deviceID})
		if errors.Is(err, store.ErrNoRows) { // a sync removed it meanwhile: the change happened, report it
			row.Tags, row.OwnerMembershipID = norm, nil
			d = deviceOf(row, "")
			return nil
		}
		d = deviceOf(r.DeviceInventoryCache, r.OwnerDisplay)
		return err
	})
	if err != nil {
		s.closeFailed(ctx, tenantID, &op, "cache_update_failed")
		return Device{}, fmt.Errorf("devices: tags: record: %w", err)
	}
	return d, nil
}
