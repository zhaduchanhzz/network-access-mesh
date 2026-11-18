//go:build !linux

package compose

import (
	"io/fs"
	"time"
)

// The helpers run in a Linux container only.
type helperEnv struct{ now func() time.Time }

func defaultHelperEnv() helperEnv { return helperEnv{now: time.Now} }

func (helperEnv) backupSnapshot(BackupHelperRequest) helperOutcome { return errorOutcome("linux only") }
func (helperEnv) restoreUnpack(RestoreHelperRequest) helperOutcome { return errorOutcome("linux only") }
func (helperEnv) dataCheck(int64) helperOutcome                    { return errorOutcome("linux only") }

func nlinkOf(fs.FileInfo) uint64 { return 1 }
