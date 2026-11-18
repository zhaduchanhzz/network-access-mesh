package config

// System settings — the keys of system_settings (§6.3) that GET/PUT /platform/settings/{key} serve (P4-T03a; §4.2
// "config: đọc/ghi system_settings"). The set is closed: a key is either a configuration value an operator may set
// through the API (Writable, with its validator — the readers of the key take exactly what it accepts), or a value
// written only by a host command and shown read-only (maintenance — P3-T17), or internal state that is never served
// (the read cursors idp.audit_sync.<kind>.<realm> of P3-T15 — §6.3: "PUT /platform/settings/{key} từ chối các khóa này").

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// SystemSetting describes one served key.
type SystemSetting struct {
	Key         string
	Description string
	Writable    bool
	// Default is the value its reader uses while the row is absent (JSON); nil = the reader has no default.
	Default json.RawMessage
	// check validates and canonicalizes a value (Writable keys only).
	check func(raw []byte) ([]byte, error)
}

// Keys of the served settings.
const (
	SettingApprovalTTLHours = "approval.ttl_hours" // approvals.TTLSetting (P3-T04a): 1–168 hours
	SettingMaxTenants       = "quota.max_tenants"  // usage.TenantCapKey (P3-T06a): the tenant cap of the platform
	SettingMaintenance      = "maintenance"        // platform.MaintenanceKey (P3-T17): written by host commands only
)

// cursorPrefix is the prefix of the internal read cursors of idp.audit_sync (P3-T15): never served.
const cursorPrefix = "idp.audit_sync."

var systemSettings = []SystemSetting{
	{Key: SettingApprovalTTLHours, Writable: true, Default: json.RawMessage(`24`), check: integerIn(1, 168),
		Description: "Lifetime of a new approval request, in hours (1–168)"},
	{Key: SettingMaxTenants, Writable: true, check: integerIn(0, 2147483647),
		Description: "Maximum number of tenants that are not deleted or failed (tenant creation quota)"},
	{Key: SettingMaintenance, Writable: false,
		Description: "Persistent maintenance flag — written by meshguard admin maintenance / post-restore-reconcile only"},
}

// SystemSettings lists the served keys, sorted.
func SystemSettings() []SystemSetting {
	out := slices.Clone(systemSettings)
	slices.SortFunc(out, func(a, b SystemSetting) int { return strings.Compare(a.Key, b.Key) })
	return out
}

// LookupSystemSetting returns the served key (false for an unknown key and for the internal cursors).
func LookupSystemSetting(key string) (SystemSetting, bool) {
	if strings.HasPrefix(key, cursorPrefix) {
		return SystemSetting{}, false
	}
	for _, s := range systemSettings {
		if s.Key == key {
			return s, true
		}
	}
	return SystemSetting{}, false
}

// ErrSettingValue is a value a writable key does not accept.
var ErrSettingValue = errors.New("config: invalid setting value")

// ErrSettingReadOnly is a write to a key that is not writable through the API.
var ErrSettingReadOnly = errors.New("config: setting is read-only")

// CheckValue validates a value for the key and returns its canonical JSON.
func (s SystemSetting) CheckValue(raw []byte) ([]byte, error) {
	if !s.Writable || s.check == nil {
		return nil, ErrSettingReadOnly
	}
	return s.check(raw)
}

// integerIn accepts a JSON integer within [lo, hi] (no fraction, no exponent, no string) — the readers parse the
// stored text with strconv (approvals.ttl) or as a JSON integer (usage.limitValue).
func integerIn(lo, hi int64) func([]byte) ([]byte, error) {
	return func(raw []byte) ([]byte, error) {
		t := bytes.TrimSpace(raw)
		n, err := strconv.ParseInt(string(t), 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != string(t) || n < lo || n > hi {
			return nil, fmt.Errorf("%w: an integer within %d…%d", ErrSettingValue, lo, hi)
		}
		return []byte(strconv.FormatInt(n, 10)), nil
	}
}
