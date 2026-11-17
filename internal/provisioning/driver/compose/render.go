package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Repositories of the Headscale images a tenant may run (versions.lock — TestRepositoriesMatchVersionsLock): the
// MeshGuard build with the V-26 patch ([images.mg-headscale], P2-T10a) and the official image kept for rollback
// ([images.headscale]). They only choose the comment line "Headscale: …" of compose.yaml, as render_instance.py does.
const (
	PatchedRepository  = "ghcr.io/zhaduchanhzz/network-access-mesh/headscale"
	OfficialRepository = "docker.io/headscale/headscale"
)

// InitialRecords is records/extra-records.json of a new instance: never empty, never null — Headscale ignores an empty
// file (§11.3 step 8). The agent writes it only when the file does not exist: WriteDnsRecords owns it afterwards.
const InitialRecords = "[]\n"

// Rendered is the configuration of one instance, rendered from the embedded templates.
type Rendered struct {
	Compose []byte // compose.yaml
	Config  []byte // config/config.yaml
	Policy  []byte // config/bootstrap-policy.hujson
	// ConfigSHA256 is sha256(config.yaml) — meta/instance.json, instance_config_versions (§11.3 step 8).
	ConfigSHA256 string
	// Image is <repository>@sha256:<digest> — the reference compose.yaml runs.
	Image string
}

// headscaleNote is the comment of compose.yaml naming which Headscale build runs — the notes of render_instance.py
// (headscale_image) for a pinned image of either build.
func headscaleNote(img agentspec.AllowedImage) string {
	switch img.Repository {
	case PatchedRepository:
		return "bản vá MeshGuard (P2-T10a) — versions.lock [images.mg-headscale]"
	case OfficialRepository:
		return "image chính thức — versions.lock [images.headscale] (rollback hoặc chưa rollout: còn lỗi V-26)"
	}
	return "image do tham số chỉ định"
}

// cpus renders cpu_millis the way the parameter files write `cpus`: "1.0", "0.5", "1.25", "16.0".
func cpus(millis uint32) string {
	frac := strings.TrimRight(fmt.Sprintf("%03d", millis%1000), "0")
	if frac == "" {
		frac = "0"
	}
	return strconv.FormatUint(uint64(millis/1000), 10) + "." + frac
}

// safeValue: a rendered value never carries YAML/comment syntax or a placeholder. Every value comes from a validated
// agentspec field (UUID, slug, netip, number, allowlisted image), so this is a last line of defence, not a filter.
var safeValue = regexp.MustCompile(`^[A-Za-z0-9 ._:/@-]*$`)

// Render renders the instance of s for host h. Nothing is written; the result has passed the invariant checks of
// §11.1 (checkConfig, checkCompose).
func Render(h *agentspec.Host, s agentspec.InstanceSpec) (*Rendered, error) {
	if s.Headscale.STUNPort != 0 {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_PORT_OUT_OF_RANGE, Field: "spec.headscale.stun_port",
			Msg: fmt.Sprintf("template v%d has no per-tenant STUN port (shared STUN — §10.1)", agentspec.TemplateVersion)}
	}
	slug := s.Ref.Slug
	vars := map[string]string{
		"template_version": strconv.Itoa(agentspec.TemplateVersion),
		"tenants_dir":      h.TenantsDir,
		"slug":             slug,
		"instance_id":      s.Ref.InstanceID.String(),
		"tenant_id":        s.Ref.TenantID.String(),
		"net_cidr":         s.NetCIDR.String(),
		"run_uid":          strconv.FormatUint(uint64(s.RunUID), 10),
		"derp_region_id":   strconv.FormatUint(uint64(s.Headscale.DERPRegionID), 10),
		"derp_region_code": "mg-" + slug,
		"derp_region_name": "MeshGuard " + slug,
		"derp_ipv4":        s.Headscale.PublicEntry.String(),
		"node_expiry":      strconv.FormatUint(uint64(s.Headscale.NodeExpiryDays)*24, 10) + "h", // Headscale 0.29.7 has no day unit
		"image":            s.Image.Reference(),
		"mem_limit":        strconv.FormatUint(uint64(s.Limits.MemoryMiB), 10) + "m",
		"cpus":             cpus(s.Limits.CPUMillis),
		"pids_limit":       strconv.FormatUint(uint64(s.Limits.PIDs), 10),
		"mesh_domain":      "mesh." + h.BaseDomain,
		"tailnet_suffix":   "tail." + h.BaseDomain,
		"log_level":        s.Headscale.LogLevel,
	}
	for k, v := range vars {
		if !safeValue.MatchString(v) {
			return nil, fmt.Errorf("render: value of %s has characters outside the safe set", k)
		}
	}
	ns := make([]string, 0, len(s.Headscale.Nameservers))
	for _, a := range s.Headscale.Nameservers {
		if !safeValue.MatchString(a.String()) {
			return nil, errors.New("render: nameserver outside the safe set")
		}
		ns = append(ns, "      - "+a.String())
	}
	vars["nameservers_yaml"] = strings.Join(ns, "\n")
	vars["headscale_note"] = headscaleNote(s.Image) // constant text of this package
	config, err := substitute(templates.ConfigYAML, vars)
	if err != nil {
		return nil, fmt.Errorf("render config.yaml: %w", err)
	}
	compose, err := substitute(templates.ComposeTenant, vars)
	if err != nil {
		return nil, fmt.Errorf("render compose.yaml: %w", err)
	}
	r := &Rendered{Compose: []byte(compose), Config: []byte(config), Policy: []byte(templates.BootstrapPolicy), Image: s.Image.Reference()}
	sum := sha256.Sum256(r.Config)
	r.ConfigSHA256 = hex.EncodeToString(sum[:])
	if err := checkConfig(r.Config, h, s); err != nil {
		return nil, err
	}
	if err := checkCompose(r.Compose, h, s); err != nil {
		return nil, err
	}
	return r, nil
}

// placeholder is Python's string.Template syntax ($$, $name, ${name}); idpattern [_a-z][_a-z0-9]* case-insensitive.
var placeholder = regexp.MustCompile(`(?i)\$(?:(\$)|([_a-z][_a-z0-9]*)|\{([_a-z][_a-z0-9]*)\}|())`)

// substitute is string.Template.substitute of render_instance.py: every placeholder must have a value (a missing key
// or a lone "$" is an error), "$$" is a literal "$", and values are inserted once (never expanded again).
func substitute(tmpl string, vars map[string]string) (string, error) {
	var out strings.Builder
	last := 0
	for _, m := range placeholder.FindAllStringSubmatchIndex(tmpl, -1) {
		out.WriteString(tmpl[last:m[0]])
		last = m[1]
		switch {
		case m[2] >= 0: // $$
			out.WriteByte('$')
		case m[4] >= 0, m[6] >= 0:
			var name string
			if m[4] >= 0 {
				name = tmpl[m[4]:m[5]]
			} else {
				name = tmpl[m[6]:m[7]]
			}
			v, ok := vars[name]
			if !ok {
				return "", fmt.Errorf("template placeholder %q has no value", name)
			}
			out.WriteString(v)
		default:
			return "", fmt.Errorf("invalid placeholder at byte %d", m[0])
		}
	}
	out.WriteString(tmpl[last:])
	return out.String(), nil
}

// identityMeta is the part of meta/instance.json written at the storage phase (before anything is rendered) — what the
// guard reads (agentspec.Meta).
func identityMeta(s agentspec.InstanceSpec) map[string]any {
	return map[string]any{
		"tenant_id":   s.Ref.TenantID.String(),
		"instance_id": s.Ref.InstanceID.String(),
		"slug":        s.Ref.Slug,
		"run_uid":     json.Number(strconv.FormatUint(uint64(s.RunUID), 10)),
		"net_cidr":    s.NetCIDR.String(),
	}
}

// configMeta adds what the config phase records: the same keys and values as render_instance.py
// (template_version as a string, config_sha256, image).
func configMeta(m map[string]any, r *Rendered) {
	m["template_version"] = strconv.Itoa(agentspec.TemplateVersion)
	m["config_sha256"] = r.ConfigSHA256
	m["image"] = r.Image
}

// encodeMeta is json.dumps(meta, indent=2, sort_keys=True) + "\n" of render_instance.py (flat object, ASCII values).
func encodeMeta(m map[string]any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// decodeMeta reads meta/instance.json keeping every key (later versions add keys — noise_key_fingerprint,
// edge_attach) and numbers as written.
func decodeMeta(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, errors.New("meta/instance.json is not a JSON object")
	}
	if dec.More() {
		return nil, errors.New("meta/instance.json has trailing data")
	}
	return m, nil
}
