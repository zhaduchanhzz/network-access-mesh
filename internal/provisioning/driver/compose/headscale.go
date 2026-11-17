package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// The Headscale CLI inside the tenant container, over the instance's local Unix socket (§11.3 steps 12–13; the same
// commands infrastructure/host/tenant-deploy.sh runs by hand). The command line is fixed by the driver; nothing of a
// request reaches it but a validated number (the key TTL in hours) and an id read back from the CLI itself.

// policyFileInContainer is config/bootstrap-policy.hujson as the container sees it (config/ mounted at /etc/headscale).
const policyFileInContainer = "/etc/headscale/bootstrap-policy.hujson"

// policies maps a policy kind to the HuJSON the agent sets — the templates embedded in its binary. The suspension
// policy of §11.4 is applied by the worker through the API (policy.apply, P3-T08), not here.
var policies = map[agentv1.PolicyKind]string{
	agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL: templates.BootstrapPolicy,
}

// readBack is the policy `headscale policy get` printed: the stored HuJSON followed by exactly one newline (Println —
// RT-15), which is removed.
func readBack(out []byte) []byte {
	return bytes.TrimSuffix(out, []byte("\n"))
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// cliError is a failed CLI command: its exit code and stderr (redacted, bounded) — never its stdout, which may carry a
// key.
func cliError(what string, res ExecResult) error {
	msg := strings.TrimSpace(string(bytes.ToValidUTF8(res.Stderr, []byte("?"))))
	if len(msg) > 512 {
		msg = msg[:512] + "…"
	}
	return fmt.Errorf("headscale %s: exit code %d: %s", what, res.ExitCode, logx.RedactString(msg))
}

// BootstrapPolicy — §11.3 step 12: set the baseline deny-all policy through the CLI in the container, then read it
// back and compare sha256 (PL-02: the allow-all window of a new instance closes before it has any network path; the
// edge is attached only afterwards — EnsureEdgeAttachment checks a policy exists). A policy already equal to the
// baseline is not set again (idempotent, nothing written). An activated instance passes the start guard first.
func (d *Driver) BootstrapPolicy(ctx context.Context, c agentspec.Call, kind agentv1.PolicyKind) (*agentv1.BootstrapPolicyResponse, error) {
	want, ok := policies[kind]
	if !ok {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, Field: "policy", Msg: "unknown policy kind"}
	}
	n, l := d.cfg.Host.Names(c.Ref), newLayout(c.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	if err := d.enforceStartGuard(ctx, t, l, n, c.Ref, "policy_bootstrap"); err != nil {
		return nil, err
	}
	if _, err := d.runningContainer(ctx, n, c.Ref); err != nil {
		return nil, err
	}
	sum := sha256Hex([]byte(want))
	get := func() (ExecResult, error) {
		return d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "policy", "get", "-o", "json"}, execTimeout)
	}
	if res, err := get(); err != nil {
		return nil, err
	} else if res.ExitCode == 0 && sha256Hex(readBack(res.Stdout)) == sum {
		return &agentv1.BootstrapPolicyResponse{PolicySha256: sum}, nil
	}
	// the file the CLI reads is the one EnsureInstance(config) wrote: it must be exactly the template
	if raw, err := t.readFile(l.policyFile, agentspec.MaxPolicyBytes); err != nil {
		return nil, err
	} else if raw == nil || sha256Hex(raw) != sum {
		return nil, state("instance", "config/bootstrap-policy.hujson is not the agent's template (EnsureInstance with TARGET_PHASE_CONFIG)")
	}
	res, err := d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "policy", "set", "--file", policyFileInContainer}, execTimeout)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, cliError("policy set", res)
	}
	res, err = get()
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, cliError("policy get", res)
	}
	if got := sha256Hex(readBack(res.Stdout)); got != sum {
		return nil, state("instance", "the policy read back (sha256 %s) is not the baseline that was set (sha256 %s)", got, sum)
	}
	d.cfg.Log.Info("policy_bootstrapped", "instance_id", l.id, "policy", kind.String(), "policy_sha256", sum)
	return &agentv1.BootstrapPolicyResponse{PolicySha256: sum}, nil
}

// ---------------------------------------------------------------------------------------------------- API keys

// APIKeySecret holds a Headscale API key. It never prints itself: String, GoString, every fmt verb, JSON, text and
// slog all give [REDACTED]. Reveal is called once, to fill the RPC response — the only place the key goes (§11.3
// step 13: the key travels over the agent socket to the worker, which stores it in the SecretStore; never a log, a
// file or an error).
type APIKeySecret struct{ v string }

func (APIKeySecret) String() string               { return logx.Redacted }
func (APIKeySecret) GoString() string             { return logx.Redacted }
func (APIKeySecret) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, logx.Redacted) }
func (APIKeySecret) MarshalJSON() ([]byte, error) { return json.Marshal(logx.Redacted) }
func (APIKeySecret) MarshalText() ([]byte, error) { return []byte(logx.Redacted), nil }
func (APIKeySecret) LogValue() slog.Value         { return slog.StringValue(logx.Redacted) }

// Reveal returns the key — for the RPC response only.
func (s APIKeySecret) Reveal() string { return s.v }

// apiKeyRE is a Headscale API key (RT-12): hskey-api-<12-character public prefix>-<secret>.
var apiKeyRE = regexp.MustCompile(`^hskey-api-([A-Za-z0-9_-]{12})-([A-Za-z0-9_-]{32,128})$`)

// parseCreatedKey reads the output of `headscale apikeys create -o json`: one JSON string (RT-15). The error never
// contains the output.
func parseCreatedKey(out []byte) (APIKeySecret, string, error) {
	var s string
	if err := json.Unmarshal(bytes.TrimSpace(out), &s); err != nil {
		return APIKeySecret{}, "", fmt.Errorf("apikeys create: the output (%d bytes) is not a JSON string", len(out))
	}
	m := apiKeyRE.FindStringSubmatch(s)
	if m == nil {
		return APIKeySecret{}, "", fmt.Errorf("apikeys create: the output (%d bytes) is not a Headscale API key", len(out))
	}
	return APIKeySecret{v: s}, m[1], nil
}

// hsTime is a protobuf Timestamp as the CLI prints it (-o json: Go's encoding of the generated struct).
type hsTime struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

func (t *hsTime) time() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Unix(t.Seconds, int64(t.Nanos)).UTC()
}

// hsAPIKey is one entry of `headscale apikeys list -o json` (public part only — the CLI masks the secret).
type hsAPIKey struct {
	ID         uint64  `json:"id"`
	Prefix     string  `json:"prefix"`
	Expiration *hsTime `json:"expiration"`
	CreatedAt  *hsTime `json:"created_at"`
}

var listedPrefixRE = regexp.MustCompile(`^hskey-api-([A-Za-z0-9_-]{12})-\*\*\*$`)

// prefix is the 12-character public prefix (the CLI lists "hskey-api-<prefix>-***"; a key of an older format is
// listed by its bare prefix).
func (k hsAPIKey) prefix() string {
	if m := listedPrefixRE.FindStringSubmatch(k.Prefix); m != nil {
		return m[1]
	}
	return k.Prefix
}

// valid: not expired at now (a key without expiration never expires).
func (k hsAPIKey) valid(now time.Time) bool {
	return k.Expiration == nil || k.Expiration.time().After(now)
}

func (d *Driver) listAPIKeys(ctx context.Context, n agentspec.Names) ([]hsAPIKey, error) {
	res, err := d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "apikeys", "list", "-o", "json"}, execTimeout)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 || res.Truncated {
		return nil, cliError("apikeys list", res)
	}
	var keys []hsAPIKey // "null" when there is none
	if err := json.Unmarshal(bytes.TrimSpace(res.Stdout), &keys); err != nil {
		return nil, fmt.Errorf("apikeys list: the output (%d bytes) is not a JSON list", len(res.Stdout))
	}
	return keys, nil
}

// BootstrapAPIKey — §11.3 step 13: list the instance's API keys, expire every valid key whose prefix differs from
// keepPrefix (all of them when it is empty: a key created by an earlier attempt and never stored is no longer
// valid), then — unless a valid key with keepPrefix exists (created = false) — create one with an explicit expiration
// (`apikeys create -e <ttl> -o json`). The key is returned in the response only: never logged, never written. An
// activated instance passes the start guard first (§11.4: a control plane that lost its data gets no key).
func (d *Driver) BootstrapAPIKey(ctx context.Context, k agentspec.APIKey) (*agentv1.BootstrapApiKeyResponse, error) {
	n, l := d.cfg.Host.Names(k.Ref), newLayout(k.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	if err := d.enforceStartGuard(ctx, t, l, n, k.Ref, "apikey_bootstrap"); err != nil {
		return nil, err
	}
	if _, err := d.runningContainer(ctx, n, k.Ref); err != nil {
		return nil, err
	}
	keys, err := d.listAPIKeys(ctx, n)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var keep *hsAPIKey
	var expired uint32
	for i := range keys {
		key := keys[i]
		if !key.valid(now) {
			continue
		}
		if k.KeepPrefix != "" && key.prefix() == k.KeepPrefix && keep == nil {
			keep = &keys[i]
			continue
		}
		if key.ID == 0 {
			return nil, fmt.Errorf("apikeys list: a valid key without id")
		}
		res, err := d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "apikeys", "expire", "--id", strconv.FormatUint(key.ID, 10)}, execTimeout)
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, cliError("apikeys expire", res)
		}
		expired++
	}
	if keep != nil {
		if expired > 0 {
			d.cfg.Log.Info("api_keys_expired", "instance_id", l.id, "expired_keys", expired, "kept_prefix", keep.prefix())
		}
		return &agentv1.BootstrapApiKeyResponse{Prefix: keep.prefix(), ExpiresAt: tsOrNil(keep.Expiration), Created: false, ExpiredKeys: expired}, nil
	}
	ttl := strconv.FormatInt(int64(k.TTL/time.Hour), 10) + "h" // whole hours, 24h..8760h (agentspec)
	res, err := d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "apikeys", "create", "-e", ttl, "-o", "json"}, execTimeout)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		clear(res.Stdout)
		return nil, cliError("apikeys create", res)
	}
	secret, prefix, err := parseCreatedKey(res.Stdout)
	clear(res.Stdout)
	if err != nil {
		return nil, err
	}
	// the expiration as Headscale recorded it (and the proof the key exists)
	keys, err = d.listAPIKeys(ctx, n)
	if err != nil {
		return nil, err
	}
	var created *hsAPIKey
	for i := range keys {
		if keys[i].prefix() == prefix {
			created = &keys[i]
		}
	}
	if created == nil {
		return nil, fmt.Errorf("apikeys create: the new key (prefix %s) is not listed", prefix)
	}
	d.cfg.Log.Info("api_key_bootstrapped", "instance_id", l.id, "prefix", prefix, "expires_at", created.Expiration.time(),
		"expired_keys", expired)
	return &agentv1.BootstrapApiKeyResponse{ApiKey: secret.Reveal(), Prefix: prefix, ExpiresAt: tsOrNil(created.Expiration),
		Created: true, ExpiredKeys: expired}, nil
}

func tsOrNil(t *hsTime) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(t.time())
}

// apiKeyInfos lists the public part of the instance's API keys (GetInstanceStatus include_api_keys — reconcile).
func (d *Driver) apiKeyInfos(ctx context.Context, n agentspec.Names, ref agentspec.Ref) ([]*agentv1.ApiKeyInfo, error) {
	if _, err := d.runningContainer(ctx, n, ref); err != nil {
		return nil, err
	}
	keys, err := d.listAPIKeys(ctx, n)
	if err != nil {
		return nil, err
	}
	out := make([]*agentv1.ApiKeyInfo, 0, len(keys))
	for _, k := range keys {
		out = append(out, &agentv1.ApiKeyInfo{Prefix: k.prefix(), Expiration: tsOrNil(k.Expiration), CreatedAt: tsOrNil(k.CreatedAt)})
	}
	return out, nil
}
