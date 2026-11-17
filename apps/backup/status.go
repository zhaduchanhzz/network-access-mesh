package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Status file of one target — the source of the overdue-backup alert (§16.3; P3-T16/P6-T01 build the rule on it).
// <dest>/status.json is the reference; <dest>/status.prom carries the same numbers in the Prometheus text format
// (textfile collector). Both are replaced atomically after every run (never by a run that stopped on a configuration
// error: such a run writes nothing at all).
const (
	StatusFile   = "status.json"
	StatusProm   = "status.prom"
	StatusFormat = "meshguard-backup-status/v1"
)

// Status is the content of status.json.
type Status struct {
	Format              string    `json:"format"`
	Target              string    `json:"target"`
	UpdatedAt           time.Time `json:"updated_at"`
	MaxAgeSeconds       int64     `json:"max_age_seconds"` // a last_success older than this is overdue
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastAttempt         *Attempt  `json:"last_attempt,omitempty"`
	LastSuccess         *Attempt  `json:"last_success,omitempty"`
}

// Attempt is one run: its set id and label, when it ran, and either the files written (sha256 and size of the
// ciphertext) or the error.
type Attempt struct {
	ID         string      `json:"id"`
	Label      string      `json:"label"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
	OK         bool        `json:"ok"`
	Error      string      `json:"error,omitempty"`
	TotalBytes int64       `json:"total_bytes,omitempty"`
	Files      []FileEntry `json:"files,omitempty"`
}

// ReadStatus returns the raw status file and its decoded content.
func ReadStatus(dir string) ([]byte, *Status, error) {
	raw, err := os.ReadFile(filepath.Join(dir, StatusFile)) //nolint:gosec // fixed name in the destination
	if err != nil {
		return nil, nil, err
	}
	var st Status
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", StatusFile, err)
	}
	if st.Format != StatusFormat {
		return nil, nil, fmt.Errorf("%s: unknown format %q", StatusFile, st.Format)
	}
	return raw, &st, nil
}

func loadStatus(c *Config) *Status {
	_, st, err := ReadStatus(c.Dest)
	if err != nil || st.Target != c.Target {
		st = &Status{}
	}
	st.Format, st.Target, st.MaxAgeSeconds = StatusFormat, c.Target, int64(c.MaxAge/time.Second)
	return st
}

func recordSuccess(c *Config, m *Manifest) error {
	st := loadStatus(c)
	a := &Attempt{ID: m.ID, Label: m.Label, StartedAt: m.StartedAt, FinishedAt: m.FinishedAt, OK: true,
		TotalBytes: m.TotalBytes(), Files: m.Files}
	st.LastAttempt, st.LastSuccess, st.ConsecutiveFailures, st.UpdatedAt = a, a, 0, m.FinishedAt
	return writeStatus(c, st)
}

func recordFailure(c *Config, m *Manifest, at time.Time, cause error) error {
	st := loadStatus(c)
	msg := logx.RedactString(cause.Error())
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	st.LastAttempt = &Attempt{ID: m.ID, Label: m.Label, StartedAt: m.StartedAt, FinishedAt: at, Error: msg}
	st.ConsecutiveFailures++
	st.UpdatedAt = at
	return writeStatus(c, st)
}

func writeStatus(c *Config, st *Status) error {
	err := writeJSONAtomic(c.Dest, StatusFile, st, 0o640)
	var b bytes.Buffer
	metric := func(name, help string, v float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s{target=%q} %s\n", name, help, name, name, c.Target,
			strconv.FormatFloat(v, 'f', -1, 64))
	}
	var lastOK, lastBytes, lastAttemptOK float64
	if st.LastSuccess != nil {
		lastOK, lastBytes = float64(st.LastSuccess.FinishedAt.Unix()), float64(st.LastSuccess.TotalBytes)
	}
	if st.LastAttempt != nil && st.LastAttempt.OK {
		lastAttemptOK = 1
	}
	metric("meshguard_backup_last_success_timestamp_seconds", "End of the last successful backup (0 = never).", lastOK)
	metric("meshguard_backup_last_success_bytes", "Encrypted size of the last successful backup set.", lastBytes)
	metric("meshguard_backup_last_attempt_success", "1 if the last attempt succeeded.", lastAttemptOK)
	metric("meshguard_backup_consecutive_failures", "Failed attempts since the last success.", float64(st.ConsecutiveFailures))
	metric("meshguard_backup_max_age_seconds", "A last success older than this is overdue.", float64(st.MaxAgeSeconds))
	return errors.Join(err, writeFileAtomic(c.Dest, StatusProm, b.Bytes(), 0o640))
}

func writeJSONAtomic(dir, name string, v any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, name, append(raw, '\n'), mode)
}

// writeFileAtomic writes <dir>/.<name>.tmp, syncs it and renames it over <dir>/<name>.
func writeFileAtomic(dir, name string, data []byte, mode os.FileMode) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	_ = os.Remove(tmp)                                                                     //nolint:gosec // G703: configured directory, file name built by this package
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode) //nolint:gosec // name built here
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name)) //nolint:gosec // G703: configured directory, file name built by this package
	}
	if err == nil {
		err = syncDir(dir)
	}
	if err != nil {
		_ = os.Remove(tmp) //nolint:gosec // G703: configured directory, file name built by this package
	}
	return err
}
