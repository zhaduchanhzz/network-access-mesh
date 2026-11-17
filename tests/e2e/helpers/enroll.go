//go:build mgtestfixture

package helpers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

const (
	// MaxKeyTTL is the longest lifetime of an enrollment pre-auth key (§7.4: one-time, ≤ 15 minutes).
	MaxKeyTTL = 15 * time.Minute
	// DefaultKeyTTL is used when Options.TTL is zero.
	DefaultKeyTTL = 10 * time.Minute
	// DefaultUser is the Headscale user test clients are enrolled as when Options.User is empty.
	DefaultUser = "mg-e2e-enroll"
	// expiryTolerance absorbs the rounding of the expiration stored by Headscale when the key is read back.
	expiryTolerance = 2 * time.Second
)

// Options configures Enroll.
type Options struct {
	User        string        // Headscale user to ensure (ID-08 rules, checked by the adapter); "" = DefaultUser
	DisplayName string        // display name if the user is created
	TTL         time.Duration // lifetime of the key, in (0, MaxKeyTTL]; 0 = DefaultKeyTTL
	Now         func() time.Time
}

// Enrollment is one one-time pre-auth key issued for a test client of a tenant. Its exported fields are public
// identifiers; the key is reachable only through Key and WriteKeyFile.
type Enrollment struct {
	TenantID    uuid.UUID
	User        headscale.User
	UserCreated bool // the user did not exist: Enroll created it (Cleanup may delete it)
	KeyID       uint64
	KeyPrefix   string // public prefix of the key (never the key)
	Expiration  time.Time
	CreatedAt   time.Time

	key   headscale.Secret
	files []string
}

// Enroll ensures the Headscale user and issues a one-time pre-auth key with an explicit expiration ≤ 15 minutes, all
// through reg.ForTenant (see the package documentation).
func Enroll(ctx context.Context, reg headscale.Registry, tenantID uuid.UUID, o Options) (*Enrollment, error) {
	if o.User == "" {
		o.User = DefaultUser
	}
	if o.TTL == 0 {
		o.TTL = DefaultKeyTTL
	}
	if o.TTL < 0 || o.TTL > MaxKeyTTL {
		return nil, fmt.Errorf("enroll: TTL must be in (0, %v] (§7.4)", MaxKeyTTL)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	inst, err := reg.ForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("enroll: tenant %s: %w", tenantID, err)
	}
	user, created, err := ensureUser(ctx, inst, o.User, o.DisplayName)
	if err != nil {
		return nil, err
	}
	// §13.4: the numeric ID of a user is resolved again right before the write that uses it
	if users, err := inst.ListUsers(ctx, headscale.UserFilter{Name: o.User}); err != nil {
		return nil, fmt.Errorf("enroll: resolve user %q: %w", o.User, err)
	} else if len(users) != 1 || users[0].ID != user.ID {
		return nil, fmt.Errorf("enroll: user %q changed while enrolling (%d matches)", o.User, len(users))
	}
	exp := o.Now().Add(o.TTL).UTC().Truncate(time.Second)
	pk, err := inst.CreatePreAuthKey(ctx, headscale.PreAuthKeyOpts{User: user.ID, Reusable: false, Ephemeral: false,
		Expiration: exp})
	if err != nil {
		// not retried (§13.4 rule 3); a key the instance may have stored all the same must not stay usable
		expireMatching(ctx, inst, user.ID, exp)
		return nil, fmt.Errorf("enroll: create pre-auth key: %w", err)
	}
	e := &Enrollment{TenantID: tenantID, User: user, UserCreated: created, KeyID: pk.ID, KeyPrefix: pk.KeyPrefix,
		Expiration: exp, CreatedAt: pk.CreatedAt, key: pk.Key}
	if err := e.verifyIssued(ctx, inst); err != nil {
		_ = inst.ExpirePreAuthKey(ctx, pk.ID)
		return nil, err
	}
	return e, nil
}

// EnrollT is Enroll for a test: it fails the test on error and registers Cleanup (expire the key, delete its nodes and
// the user if Enroll created it, remove the key files) with t.Cleanup.
func EnrollT(t testing.TB, reg headscale.Registry, tenantID uuid.UUID, o Options) *Enrollment {
	t.Helper()
	e, err := Enroll(t.Context(), reg, tenantID, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := e.Cleanup(ctx, reg, CleanupOptions{DeleteNodes: true, DeleteUser: e.UserCreated}); err != nil {
			t.Errorf("enrollment cleanup: %v", err)
		}
	})
	return e
}

func ensureUser(ctx context.Context, inst headscale.Instance, name, display string) (headscale.User, bool, error) {
	users, err := inst.ListUsers(ctx, headscale.UserFilter{Name: name})
	if err != nil {
		return headscale.User{}, false, fmt.Errorf("enroll: list user %q: %w", name, err)
	}
	if len(users) == 1 {
		return users[0], false, nil
	}
	if len(users) > 1 {
		return headscale.User{}, false, fmt.Errorf("enroll: %d users named %q", len(users), name)
	}
	u, err := inst.CreateUser(ctx, headscale.CreateUser{Name: name, DisplayName: display})
	switch {
	case err == nil:
		return u, true, nil
	case errors.Is(err, headscale.ErrConflict): // created concurrently: read it back, never retry the write
		users, lerr := inst.ListUsers(ctx, headscale.UserFilter{Name: name})
		if lerr == nil && len(users) == 1 {
			return users[0], false, nil
		}
	}
	return headscale.User{}, false, fmt.Errorf("enroll: create user %q: %w", name, err)
}

// verifyIssued reads the new key back: one-time, not ephemeral, no tag, owned by the user, with the expiration asked.
func (e *Enrollment) verifyIssued(ctx context.Context, inst headscale.Instance) error {
	k, err := findKey(ctx, inst, e.KeyID)
	if err != nil {
		return fmt.Errorf("enroll: read back key %d: %w", e.KeyID, err)
	}
	var bad []string
	if k.Reusable {
		bad = append(bad, "reusable")
	}
	if k.Ephemeral {
		bad = append(bad, "ephemeral")
	}
	if len(k.Tags) > 0 {
		bad = append(bad, "tagged")
	}
	if k.User == nil || k.User.ID != e.User.ID {
		bad = append(bad, "owned by another user")
	}
	if d := k.Expiration.Sub(e.Expiration); d < -expiryTolerance || d > expiryTolerance {
		bad = append(bad, fmt.Sprintf("expiration %s instead of %s", k.Expiration.UTC().Format(time.RFC3339), e.Expiration.Format(time.RFC3339)))
	}
	if k.Used {
		bad = append(bad, "already used")
	}
	if len(bad) > 0 {
		return fmt.Errorf("enroll: key %d read back %v — expired", e.KeyID, bad)
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = k.CreatedAt
	}
	return nil
}

func findKey(ctx context.Context, inst headscale.Instance, id uint64) (headscale.PreAuthKey, error) {
	keys, err := inst.ListPreAuthKeys(ctx)
	if err != nil {
		return headscale.PreAuthKey{}, err
	}
	i := slices.IndexFunc(keys, func(k headscale.PreAuthKey) bool { return k.ID == id })
	if i < 0 {
		return headscale.PreAuthKey{}, fmt.Errorf("pre-auth key %d: %w", id, headscale.ErrNotFound)
	}
	return keys[i], nil
}

// expireMatching expires the unused keys of the user with exactly the expiration asked (best effort, after a failed
// create whose outcome is unknown).
func expireMatching(ctx context.Context, inst headscale.Instance, userID uint64, exp time.Time) {
	keys, err := inst.ListPreAuthKeys(ctx)
	if err != nil {
		return
	}
	for _, k := range keys {
		if k.User != nil && k.User.ID == userID && !k.Used && k.Expiration.Sub(exp).Abs() <= expiryTolerance {
			_ = inst.ExpirePreAuthKey(ctx, k.ID)
		}
	}
}

// Key returns the pre-auth key. It is a headscale.Secret: printing it shows [REDACTED]; Reveal only where the value
// must leave the process (a client's key file — prefer WriteKeyFile).
func (e *Enrollment) Key() headscale.Secret { return e.key }

// summary is the only text form of an enrollment: fmt prints unexported fields of a struct without their methods, so
// without Format a %+v of an Enrollment would print the key.
func (e Enrollment) summary() string {
	return fmt.Sprintf("helpers.Enrollment{tenant=%s user=%s(%d) key_id=%d key_prefix=%s expires=%s key=%s}", e.TenantID,
		e.User.Name, e.User.ID, e.KeyID, e.KeyPrefix, e.Expiration.Format(time.RFC3339), logx.Redacted)
}

// Format prints the summary for every verb (%v, %+v, %#v, %s, …).
func (e Enrollment) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.summary()) }

// LogValue keeps the key out of slog records (the JSON handler already skips unexported fields; the text handler
// would not).
func (e Enrollment) LogValue() slog.Value { return slog.StringValue(e.summary()) }

// WriteKeyFile writes the key into a new file of dir (created 0700 if missing), mode 0600, no trailing newline, for a
// client container (TS_AUTHKEY=file:<path>, tailscale up --auth-key=file:<path>). RemoveKeyFiles deletes it.
func (e *Enrollment) WriteKeyFile(dir string) (string, error) {
	if e.key.IsZero() {
		return "", errors.New("enroll: this enrollment holds no key (resumed from State)")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("enroll: key directory: %w", err)
	}
	f, err := os.CreateTemp(dir, fmt.Sprintf("authkey-%d-*", e.KeyID)) // O_EXCL, mode 0600
	if err != nil {
		return "", fmt.Errorf("enroll: key file: %w", err)
	}
	path := f.Name()
	e.files = append(e.files, path)
	_, werr := f.WriteString(e.key.Reveal())
	cerr := f.Chmod(0o600)
	if err := errors.Join(werr, cerr, f.Close()); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("enroll: write key file: %w", err)
	}
	return path, nil
}

// KeyFiles lists the key files written and not removed yet.
func (e *Enrollment) KeyFiles() []string { return slices.Clone(e.files) }

// RemoveKeyFiles deletes every key file written (a file already gone is not an error).
func (e *Enrollment) RemoveKeyFiles() error {
	var errs []error
	for _, p := range e.files {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	e.files = nil
	return errors.Join(errs...)
}

// Nodes returns the nodes of the user registered with this key (PreAuthKeyID), as ListNodes reports them.
func (e *Enrollment) Nodes(ctx context.Context, reg headscale.Registry) ([]headscale.Node, error) {
	inst, err := reg.ForTenant(ctx, e.TenantID)
	if err != nil {
		return nil, err
	}
	nodes, err := inst.ListNodes(ctx, e.User.Name)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(nodes, func(n headscale.Node) bool { return n.PreAuthKeyID != e.KeyID }), nil
}

// KeyState returns the key as the instance reports it now (Used, Expiration — never the secret).
func (e *Enrollment) KeyState(ctx context.Context, reg headscale.Registry) (headscale.PreAuthKey, error) {
	inst, err := reg.ForTenant(ctx, e.TenantID)
	if err != nil {
		return headscale.PreAuthKey{}, err
	}
	return findKey(ctx, inst, e.KeyID)
}

// CleanupOptions selects what Cleanup undoes besides expiring the key and removing the key files.
type CleanupOptions struct {
	DeleteNodes bool // delete the nodes registered with this key
	DeleteUser  bool // delete the user (only if it has no node left — Headscale refuses otherwise)
}

// Cleanup removes the key files, expires the key (harmless when used or expired), and deletes the nodes and the user
// as asked; the user is resolved again by name before it is deleted (§13.4).
func (e *Enrollment) Cleanup(ctx context.Context, reg headscale.Registry, o CleanupOptions) error {
	errs := []error{e.RemoveKeyFiles()}
	inst, err := reg.ForTenant(ctx, e.TenantID)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	if k, err := findKey(ctx, inst, e.KeyID); err == nil && k.Expiration.After(time.Now()) {
		errs = append(errs, inst.ExpirePreAuthKey(ctx, e.KeyID))
	}
	if o.DeleteNodes {
		nodes, err := e.Nodes(ctx, reg)
		errs = append(errs, err)
		for _, n := range nodes {
			if err := inst.DeleteNode(ctx, n.ID); err != nil && !errors.Is(err, headscale.ErrNotFound) {
				errs = append(errs, err)
			}
		}
	}
	if o.DeleteUser {
		users, err := inst.ListUsers(ctx, headscale.UserFilter{Name: e.User.Name})
		errs = append(errs, err)
		if err == nil && len(users) == 1 && users[0].ID == e.User.ID {
			if err := inst.DeleteUser(ctx, e.User.ID); err != nil && !errors.Is(err, headscale.ErrNotFound) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// State is what a multi-step runner keeps between processes: public identifiers only, never the key.
type State struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	UserID      uint64    `json:"user_id"`
	UserName    string    `json:"user_name"`
	UserCreated bool      `json:"user_created"`
	KeyID       uint64    `json:"key_id"`
	KeyPrefix   string    `json:"key_prefix"`
	Expiration  time.Time `json:"expiration"`
	CreatedAt   time.Time `json:"created_at"`
	KeyFiles    []string  `json:"key_files,omitempty"`
}

// State returns the public state of the enrollment.
func (e *Enrollment) State() State {
	return State{TenantID: e.TenantID, UserID: e.User.ID, UserName: e.User.Name, UserCreated: e.UserCreated,
		KeyID: e.KeyID, KeyPrefix: e.KeyPrefix, Expiration: e.Expiration, CreatedAt: e.CreatedAt, KeyFiles: slices.Clone(e.files)}
}

// Resume rebuilds an enrollment from its State, without the key (Nodes, KeyState, RemoveKeyFiles and Cleanup work).
func Resume(s State) *Enrollment {
	return &Enrollment{TenantID: s.TenantID, User: headscale.User{ID: s.UserID, Name: s.UserName}, UserCreated: s.UserCreated,
		KeyID: s.KeyID, KeyPrefix: s.KeyPrefix, Expiration: s.Expiration, CreatedAt: s.CreatedAt, files: slices.Clone(s.KeyFiles)}
}
