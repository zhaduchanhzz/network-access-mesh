package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Limits of the directory archive (the edge's ACME volume holds a few hundred small files).
const (
	MaxTarFileBytes  = 64 << 20
	MaxTarTotalBytes = 1 << 30
)

// WriteTar writes a tar archive (PAX) of root to w: directories, regular files and symbolic links with their numeric
// owner, permission bits and modification time, names relative to root ("./" is root itself). Any other file type,
// a file larger than MaxTarFileBytes or an archive larger than MaxTarTotalBytes fails the archive (fail closed);
// a file that disappears during the walk (a lock released by the edge) is skipped. Symbolic links are archived, never
// followed. Each regular file is read whole before its header is written, so a file changing size while it is read
// cannot corrupt the archive.
func WriteTar(ctx context.Context, w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path != root {
				return nil
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		var data []byte
		if fi.Mode().IsRegular() {
			// read through one descriptor and describe what was read (a file renamed over by the edge is archived
			// in its new version, never as a mix of two)
			data, fi, err = readRegular(path)
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
		}
		hdr, err := tarHeader(rel, fi)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			hdr.Typeflag = tar.TypeDir
			if rel != "." {
				hdr.Name += "/"
			}
		case fi.Mode().IsRegular():
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(data))
			total += hdr.Size
			if total > MaxTarTotalBytes {
				return fmt.Errorf("archive larger than %d bytes", MaxTarTotalBytes)
			}
		case fi.Mode()&fs.ModeSymlink != 0:
			hdr.Typeflag = tar.TypeSymlink
			if hdr.Linkname, err = os.Readlink(path); err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
		default:
			return fmt.Errorf("%s: unsupported file type %s (only directories, regular files and symlinks)", rel, fi.Mode().Type())
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if len(data) > 0 {
			if _, err := tw.Write(data); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// tarHeader builds the header of one entry from its metadata (numeric owner, permission and special bits, mtime).
func tarHeader(rel string, fi os.FileInfo) (*tar.Header, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s: no owner information", rel)
	}
	hdr := &tar.Header{
		Name:    "./" + filepath.ToSlash(rel),
		Mode:    int64(fi.Mode().Perm()),
		Uid:     int(st.Uid),
		Gid:     int(st.Gid),
		ModTime: fi.ModTime(),
		Format:  tar.FormatPAX,
	}
	if rel == "." {
		hdr.Name = "./"
	}
	if fi.Mode()&fs.ModeSetuid != 0 {
		hdr.Mode |= 0o4000
	}
	if fi.Mode()&fs.ModeSetgid != 0 {
		hdr.Mode |= 0o2000
	}
	if fi.Mode()&fs.ModeSticky != 0 {
		hdr.Mode |= 0o1000
	}
	return hdr, nil
}

// readRegular opens a file without following a symlink swapped in after the walk saw it (and without blocking on a
// FIFO), checks that what it opened is a regular file and returns its content with the metadata of that same open
// file.
func readRegular(path string) ([]byte, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // walking the source directory
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, errors.New("is no longer a regular file")
	}
	if fi.Size() > MaxTarFileBytes {
		return nil, nil, fmt.Errorf("file larger than %d bytes", MaxTarFileBytes)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(f, MaxTarFileBytes+1)); err != nil {
		return nil, nil, err
	}
	if buf.Len() > MaxTarFileBytes {
		return nil, nil, fmt.Errorf("file larger than %d bytes", MaxTarFileBytes)
	}
	return buf.Bytes(), fi, nil
}
