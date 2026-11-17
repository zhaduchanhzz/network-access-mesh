//go:build unix

package compose

import (
	"io/fs"
	"syscall"
)

// fileOwner returns the owner UID and GID of a file.
func fileOwner(fi fs.FileInfo) (int, int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
