package enrollment

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Operating systems of GET /enrollment/instructions (enum EnrollmentOS).
var OperatingSystems = []string{"linux", "windows", "macos", "ios", "android"}

// Instructions is the answer of GET /enrollment/instructions (§9.4 "Hướng dẫn enrollment"): how to install the official
// client and join this tenant — never a credential.
type Instructions struct {
	OS                string
	LoginServer       string
	Steps             []string
	WebAuthCommand    *string // nil: the tenant turned web-auth off, or the platform cannot set the hostname (mobile)
	PreauthKeyCommand *string
	PrivacyNotice     string
	ManagedEnv        map[string]string
	// SelfEnroll is enrollment.self_enroll of the tenant: false ⇒ an End User's request is refused (condition self_enroll
	// of §8.6), so the Portal shows that instead of the wizard (G4b-E3). Not a secret: every member may know it.
	SelfEnroll bool
}

// PrivacyNotice is the notice of HS-22: the client may send diagnostic logs to Tailscale Inc. before its first successful
// connection, unless managed installs set TS_NO_LOGS_NO_SUPPORT.
const PrivacyNotice = "The official Tailscale client may send diagnostic logs to Tailscale Inc. before it first connects " +
	"to this network. Managed installations should set TS_NO_LOGS_NO_SUPPORT=true (or pass --no-logs-no-support)."

// Instructions is GET /tenants/{t}/enrollment/instructions?os=….
func (s *Service) Instructions(ctx context.Context, tenantID uuid.UUID, os string) (Instructions, error) {
	steps, ok := installSteps[os]
	if !ok {
		return Instructions{}, invalid("os", "invalid_os", "os must be linux, windows, macos, ios or android")
	}
	var out Instructions
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		row, err := q.GetEnrollmentContext(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) || err == nil && row.ServerUrl == nil {
			return notFound("no_instance")
		}
		if err != nil {
			return err
		}
		ls := *row.ServerUrl
		set := settingsOf(row.Settings).Enrollment
		out = Instructions{OS: os, LoginServer: ls, Steps: append([]string{}, steps...), PrivacyNotice: PrivacyNotice,
			ManagedEnv: map[string]string{"TS_NO_LOGS_NO_SUPPORT": "true"}, SelfEnroll: set.SelfEnroll}
		mobile := os == "ios" || os == "android"
		if set.WebAuthEnabled && !mobile {
			c := webAuthCommand(ls, HostnamePrefix+"<code>")
			out.WebAuthCommand = &c
		}
		if !mobile {
			c := preauthCommand(ls)
			if os == "windows" {
				c = "tailscale up --login-server=" + ls + " --auth-key=$env:TS_AUTHKEY"
			}
			out.PreauthKeyCommand = &c
		}
		return nil
	})
	return out, err
}

var installSteps = map[string][]string{
	"linux": {
		"Install the official Tailscale client from the distribution's package repository (pkgs.tailscale.com).",
		"Create a device request in the Portal (Add device) and keep this page open in the same browser session.",
		"Run the command shown by the Portal with sudo; it prints a sign-in link — open it and confirm in the Portal.",
	},
	"windows": {
		"Install the official Tailscale client for Windows (MSI from tailscale.com/download).",
		"Create a device request in the Portal (Add device) and keep this page open in the same browser session.",
		"Run the command shown by the Portal in an elevated PowerShell; open the sign-in link it prints and confirm in the Portal.",
	},
	"macos": {
		"Install the official Tailscale client for macOS (standalone package or App Store).",
		"Create a device request in the Portal (Add device) and keep this page open in the same browser session.",
		"Run the command shown by the Portal in Terminal; open the sign-in link it prints and confirm in the Portal.",
	},
	"ios": {
		"Install the official Tailscale app from the App Store.",
		"Mobile clients cannot choose their hostname: ask the Portal for a single-use pre-auth key (Add device → key).",
		"In the app, choose a custom coordination server (Settings → Accounts → Use a custom coordination server), enter the login server shown here and the key.",
	},
	"android": {
		"Install the official Tailscale app from Google Play.",
		"Mobile clients cannot choose their hostname: ask the Portal for a single-use pre-auth key (Add device → key).",
		"In the app, choose a custom coordination server (Accounts → Use an alternate server), enter the login server shown here and the key.",
	},
}
