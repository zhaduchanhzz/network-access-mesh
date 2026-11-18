package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// PostRestoreReconcile — §17.2 step 5, over the Headscale CLI in the restored container (the edge is still detached:
// nothing reaches the instance from outside until the worker attaches it after this). Every pre-auth key of the
// restored database is expired; the nodes the worker lists as revoked or deleted after the backup — matched by
// machine key, never by numeric id (the restored id counter may hand an old id to another device) — are expired or
// deleted again; every node of an offboarded member's Headscale user is expired; approved routes and tags are reset
// to the PostgreSQL state (not on the "PostgreSQL older than the backup" branch, where PostgreSQL has nothing newer to
// impose); finally every API key of the restored database is expired and a new one created (BootstrapAPIKey with no
// prefix to keep) — the keys inside the archive are dead before the hostname answers again.
func (d *Driver) PostRestoreReconcile(ctx context.Context, rc agentspec.Reconcile) (*agentv1.PostRestoreReconcileResponse, error) {
	n, l := d.cfg.Host.Names(rc.Ref), newLayout(rc.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	if err := d.enforceStartGuard(ctx, t, l, n, rc.Ref, "post_restore_reconcile"); err != nil {
		_ = t.Close()
		return nil, err
	}
	_ = t.Close()
	if _, err := d.runningContainer(ctx, n, rc.Ref); err != nil {
		return nil, err
	}
	out := &agentv1.PostRestoreReconcileResponse{}
	cli := hsCLI{d: d, ctx: ctx, container: n.Container}
	// pre-auth keys: every one still valid is expired
	keys, err := cli.preAuthKeys()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, k := range keys {
		if k.Expiration != nil && !k.Expiration.time().After(now) {
			continue
		}
		if err := cli.run("preauthkeys expire", "preauthkeys", "expire", "--id", strconv.FormatUint(k.ID, 10)); err != nil {
			return nil, err
		}
		out.PreauthKeysExpired++
	}
	nodes, err := cli.nodes()
	if err != nil {
		return nil, err
	}
	byKey := map[string]hsNode{}
	for _, nd := range nodes {
		byKey[nd.MachineKey] = nd
	}
	unmatched := map[string]bool{}
	expired := map[uint64]bool{}
	expire := func(nd hsNode) error {
		if expired[nd.ID] || nd.expired(now) {
			expired[nd.ID] = true
			return nil
		}
		if err := cli.run("nodes expire", "nodes", "expire", "--identifier", strconv.FormatUint(nd.ID, 10)); err != nil {
			return err
		}
		expired[nd.ID] = true
		out.NodesExpired++
		return nil
	}
	for _, mk := range rc.RevokedMachineKeys {
		nd, ok := byKey[mk]
		if !ok {
			unmatched[mk] = true
			continue
		}
		if err := expire(nd); err != nil {
			return nil, err
		}
	}
	deleted := map[uint64]bool{}
	for _, mk := range rc.DeletedMachineKeys {
		nd, ok := byKey[mk]
		if !ok {
			unmatched[mk] = true
			continue
		}
		if err := cli.run("nodes delete", "nodes", "delete", "--identifier", strconv.FormatUint(nd.ID, 10), "--force"); err != nil {
			return nil, err
		}
		deleted[nd.ID] = true
		out.NodesDeleted++
	}
	if len(rc.OffboardedUsers) > 0 {
		gone := map[string]bool{}
		for _, u := range rc.OffboardedUsers {
			gone[u] = true
		}
		users := map[string]bool{}
		for _, nd := range nodes {
			if nd.User == nil || !gone[nd.User.Name] || deleted[nd.ID] {
				continue
			}
			users[nd.User.Name] = true
			if err := expire(nd); err != nil {
				return nil, err
			}
		}
		out.UsersHandled = uint32(len(users)) //nolint:gosec // G115: ≤ MaxListItems
	}
	if !rc.RestorePointIsOlder {
		for _, want := range rc.Nodes {
			nd, ok := byKey[want.MachineKey]
			if !ok {
				unmatched[want.MachineKey] = true
				continue
			}
			if deleted[nd.ID] {
				continue
			}
			if !samePrefixes(nd.ApprovedRoutes, want.ApprovedRoutes) {
				routes := make([]string, 0, len(want.ApprovedRoutes))
				for _, p := range want.ApprovedRoutes {
					routes = append(routes, p.String())
				}
				if err := cli.run("nodes approve-routes", "nodes", "approve-routes", "--identifier", strconv.FormatUint(nd.ID, 10),
					"--routes", strings.Join(routes, ",")); err != nil {
					return nil, err
				}
				out.RoutesReset++
			}
			if !sameStrings(nd.Tags, want.Tags) {
				if len(want.Tags) == 0 {
					out.TagsNotReset = append(out.TagsNotReset, want.MachineKey)
					continue
				}
				if err := cli.run("nodes tag", "nodes", "tag", "--identifier", strconv.FormatUint(nd.ID, 10), "--tags", strings.Join(want.Tags, ",")); err != nil {
					return nil, err
				}
				out.TagsReset++
			}
		}
	}
	for mk := range unmatched {
		out.UnmatchedMachineKeys = append(out.UnmatchedMachineKeys, mk)
	}
	slices.Sort(out.UnmatchedMachineKeys)
	slices.Sort(out.TagsNotReset)
	// API keys last: every key of the restored database is expired, one new key is created (and returned only here)
	k, err := d.BootstrapAPIKey(ctx, agentspec.APIKey{Call: rc.Call, TTL: rc.APIKeyTTL})
	if err != nil {
		return nil, err
	}
	out.ApiKey, out.ApiKeyPrefix, out.ApiKeyExpiresAt, out.ApiKeysExpired = k.GetApiKey(), k.GetPrefix(), k.GetExpiresAt(), k.GetExpiredKeys()
	d.cfg.Log.Info("post_restore_reconciled", "instance_id", l.id, "preauth_keys_expired", out.PreauthKeysExpired,
		"nodes_expired", out.NodesExpired, "nodes_deleted", out.NodesDeleted, "routes_reset", out.RoutesReset, "tags_reset", out.TagsReset,
		"tags_not_reset", len(out.TagsNotReset), "users_handled", out.UsersHandled, "unmatched", len(out.UnmatchedMachineKeys),
		"api_keys_expired", out.ApiKeysExpired, "api_key_prefix", out.ApiKeyPrefix, "restore_point_older", rc.RestorePointIsOlder)
	return out, nil
}

// hsCLI runs Headscale CLI commands in the instance's container (fixed command lines; numeric ids read back from the
// CLI itself; validated CIDRs and tags only).
type hsCLI struct {
	d         *Driver
	ctx       context.Context
	container string
}

func (c hsCLI) exec(args ...string) (ExecResult, error) {
	return c.d.cfg.Engine.Exec(c.ctx, c.container, append([]string{headscaleBin}, args...), execTimeout)
}

func (c hsCLI) run(what string, args ...string) error {
	res, err := c.exec(append(args, "-o", "json")...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cliError(what, res)
	}
	return nil
}

func (c hsCLI) list(what string, v any, args ...string) error {
	res, err := c.exec(append(args, "-o", "json-line")...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 || res.Truncated {
		return cliError(what, res)
	}
	if err := json.Unmarshal(bytes.TrimSpace(res.Stdout), v); err != nil {
		return fmt.Errorf("%s: the output (%d bytes) is not a JSON list", what, len(res.Stdout))
	}
	return nil
}

// hsNode is one entry of `headscale nodes list -o json`.
type hsNode struct {
	ID         uint64 `json:"id"`
	MachineKey string `json:"machine_key"`
	User       *struct {
		ID   uint64 `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
	Expiry         *hsTime  `json:"expiry"`
	ApprovedRoutes []string `json:"approved_routes"`
	Tags           []string `json:"tags"`
}

// expired: an expiry set (Headscale prints the zero time 0001-01-01 for "never") and not after now.
func (n hsNode) expired(now time.Time) bool {
	if n.Expiry == nil || n.Expiry.Seconds <= 0 {
		return false
	}
	return !n.Expiry.time().After(now)
}

func (c hsCLI) nodes() ([]hsNode, error) {
	var out []hsNode
	if err := c.list("nodes list", &out, "nodes", "list"); err != nil {
		return nil, err
	}
	for _, nd := range out {
		if nd.ID == 0 || !strings.HasPrefix(nd.MachineKey, "mkey:") {
			return nil, fmt.Errorf("nodes list: an entry without id or machine key")
		}
	}
	return out, nil
}

// hsPreAuthKey is one entry of `headscale preauthkeys list -o json` (the key itself is masked by the CLI).
type hsPreAuthKey struct {
	ID         uint64  `json:"id"`
	Expiration *hsTime `json:"expiration"`
}

func (c hsCLI) preAuthKeys() ([]hsPreAuthKey, error) {
	var out []hsPreAuthKey
	if err := c.list("preauthkeys list", &out, "preauthkeys", "list"); err != nil {
		return nil, err
	}
	for _, k := range out {
		if k.ID == 0 {
			return nil, fmt.Errorf("preauthkeys list: an entry without id")
		}
	}
	return out, nil
}

func samePrefixes(have []string, want []netip.Prefix) bool {
	a := make([]string, 0, len(have))
	for _, s := range have {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return false
		}
		a = append(a, p.Masked().String())
	}
	b := make([]string, 0, len(want))
	for _, p := range want {
		b = append(b, p.String())
	}
	return sameStrings(a, b)
}

func sameStrings(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}
