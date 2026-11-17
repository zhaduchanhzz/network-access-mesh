//go:build linux

package compose

import (
	"io/fs"
	"syscall"
)

func identity(fi fs.FileInfo) fileID {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{dev: st.Dev, ino: st.Ino, size: st.Size, mtime: st.Mtim.Nano(), ctime: st.Ctim.Nano(), ok: true}
}
