// Package templates embeds the templates of a tenant's Headscale instance (§14.5 of the master plan): ONE source for
// both renderers — tools/render_instance.py (Phase 1–2, Python string.Template) and the Host Agent's compose driver
// (internal/provisioning/driver/compose, P3-T02), which renders them inside its own image from typed parameters
// only. Both produce the same bytes for the same parameters (golden and parity tests of the compose driver).
//
// Changing a template changes config_sha256 of every instance rendered afterwards: bump TEMPLATE_VERSION of
// render_instance.py and agentspec.TemplateVersion together, then update tests/golden/headscale.
package templates

import _ "embed" // the templates are compiled into the agent binary (no runtime file, nothing on the host to tamper with)

// ConfigYAML is config.yaml.tmpl (Headscale config.yaml).
//
//go:embed config.yaml.tmpl
var ConfigYAML string

// ComposeTenant is compose.tenant.yaml.tmpl (compose project mg-t-<slug>).
//
//go:embed compose.tenant.yaml.tmpl
var ComposeTenant string

// BootstrapPolicy is the baseline deny-all policy (bootstrap-policy.hujson), copied verbatim.
//
//go:embed bootstrap-policy.hujson
var BootstrapPolicy string

// SuspensionPolicy is the deny-all policy a suspended tenant gets (suspension-policy.hujson — §11.4, P3-T08), stored as
// a policy version of kind suspension; the tenant's desired version is kept and re-applied by resume.
//
//go:embed suspension-policy.hujson
var SuspensionPolicy string
