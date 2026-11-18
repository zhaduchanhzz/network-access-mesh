package config

import (
	"errors"
	"strings"
	"time"
)

// Deprovision configures the deletion of tenants in the worker (P3-T09, §11.4, §6.1): KeyGrace
// (MG_DEPROVISION_KEY_GRACE, default 720h = 30 days) is the time between the deletion of a tenant and the destruction
// of its keys (crypto-shredding by tenant.keys_destroy) — the final backup is kept at least this long and the online
// restore of it is possible only within it.
type Deprovision struct {
	KeyGrace time.Duration
}

// LoadDeprovision reads MG_DEPROVISION_* (worker only). Errors name variables, never values.
func LoadDeprovision(service string, getenv func(string) string) (Deprovision, []error) {
	var d Deprovision
	if service != "worker" {
		return d, nil
	}
	var err error
	if d.KeyGrace, err = time.ParseDuration(withDefault(strings.TrimSpace(getenv("MG_DEPROVISION_KEY_GRACE")), "720h")); err != nil ||
		d.KeyGrace < 24*time.Hour || d.KeyGrace > 400*24*time.Hour {
		return d, []error{errors.New("MG_DEPROVISION_KEY_GRACE: a duration in [24h, 9600h]")}
	}
	return d, nil
}
