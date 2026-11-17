//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// peerCred returns the credentials the kernel recorded for the peer when it connected (SO_PEERCRED): they cannot
// be forged from user space. In rootful Docker without userns-remap the values are host UIDs/GIDs.
func peerCred(conn net.Conn) (uid, gid uint32, pid int32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, 0, errors.New("not a Unix socket connection")
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := rc.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) //nolint:gosec // G115: a file descriptor fits in int
	}); err != nil {
		return 0, 0, 0, err
	}
	if serr != nil {
		return 0, 0, 0, fmt.Errorf("SO_PEERCRED: %w", serr)
	}
	return cred.Uid, cred.Gid, cred.Pid, nil
}

// listenUnix creates the socket with mode 0600 from the start (umask), then opens it to the worker's group: 0660,
// group gid (-1: unchanged). The directory must be owned by the agent and not writable by group or others, so no
// other process can replace the socket; a stale socket from a previous run is removed — anything else at the path
// is refused.
func listenUnix(ctx context.Context, path string, gid int) (net.Listener, error) {
	dir := filepath.Dir(path)
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("socket directory: %w", err)
	}
	if !fi.IsDir() || !ownedBy(fi, os.Geteuid()) || fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("socket directory %s must be a directory owned by the agent, not writable by group or others", dir)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket — refusing to remove it", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("stale socket: %w", err)
		}
	}
	old := syscall.Umask(0o177)
	l, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("socket group: %w", err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // G302: the worker connects through its group
		_ = l.Close()
		return nil, fmt.Errorf("socket mode: %w", err)
	}
	return l, nil
}

func ownedBy(fi fs.FileInfo, uid int) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}
