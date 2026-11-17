//go:build unix

package agentspec

import (
	"io/fs"
	"syscall"
)

// fileOwner returns the owner UID of a file.
func fileOwner(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
