package compose

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Storage of one host's tenants directory (§14.2). Every path is relative to an os.Root opened at the tenants
// directory: ".." and symlinks cannot leave it. On top of that, an existing path where the agent expects a directory
// or a regular file must BE one — a symlink there is refused (UNSAFE_PATH), never followed, replaced or removed.

const (
	modeInstanceDir = 0o750 // root:run_gid — the tenant traverses it, never writes (§11.3 step 7)
	modeConfigDir   = 0o750 // root:run_gid, mounted read-only
	modeMetaDir     = 0o700 // root:root
	modeDataDir     = 0o700 // run_uid:run_gid — the only path the tenant owns
	modeTenantFile  = 0o440 // root:run_gid — config.yaml, bootstrap-policy.hujson, extra-records.json
	modeCompose     = 0o440 // root:root — compose.yaml
	modeMeta        = 0o400 // root:root — meta/instance.json
	maxReadBytes    = 1 << 20
)

// owner is the owner (uid, gid) and permission bits a path must have.
type owner struct {
	uid, gid int
	mode     fs.FileMode
}

// tree is the tenants directory of the host.
type tree struct {
	root *os.Root
	// agent is the owner of every agent path (its euid:egid — 0:0 in production).
	agentUID, agentGID int
}

func openTree(dir string, uid, gid int) (*tree, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("tenants directory: %w", err)
	}
	return &tree{root: r, agentUID: uid, agentGID: gid}, nil
}

func (t *tree) Close() error { return t.root.Close() }

func unsafePath(rel, what string) error {
	return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, Field: "instance",
		Msg: fmt.Sprintf("%s: %s (never followed, replaced or adopted)", filepath.ToSlash(rel), what)}
}

// lstat returns nil, nil when the path does not exist.
func (t *tree) lstat(rel string) (fs.FileInfo, error) {
	fi, err := t.root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.ToSlash(rel), err)
	}
	return fi, nil
}

// fix sets the owner and mode of an existing path that lstat showed to be of the right type.
func (t *tree) fix(rel string, fi fs.FileInfo, o owner) (bool, error) {
	uid, gid, ok := fileOwner(fi)
	changed := false
	if !ok || uid != o.uid || gid != o.gid {
		if err := t.root.Lchown(rel, o.uid, o.gid); err != nil {
			return false, fmt.Errorf("chown %s: %w", filepath.ToSlash(rel), err)
		}
		changed = true
	}
	// chown may clear set-id bits; compare the whole permission set after it
	if fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != o.mode || changed {
		if err := t.root.Chmod(rel, o.mode); err != nil {
			return false, fmt.Errorf("chmod %s: %w", filepath.ToSlash(rel), err)
		}
		changed = true
	}
	return changed, nil
}

// ensureDir makes rel a directory with owner o. An absent directory is created only when create is set (otherwise
// errMissing). A symlink or anything else than a directory is refused.
func (t *tree) ensureDir(rel string, o owner, create bool) (bool, error) {
	fi, err := t.lstat(rel)
	if err != nil {
		return false, err
	}
	if fi == nil {
		if !create {
			return false, fmt.Errorf("%s: %w", filepath.ToSlash(rel), errMissing)
		}
		if err := t.root.Mkdir(rel, 0o700); err != nil {
			return false, fmt.Errorf("mkdir %s: %w", filepath.ToSlash(rel), err)
		}
		if fi, err = t.root.Lstat(rel); err != nil {
			return false, err
		}
		if _, err := t.fix(rel, fi, o); err != nil {
			return false, err
		}
		return true, nil
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return false, unsafePath(rel, "not a directory")
	}
	return t.fix(rel, fi, o)
}

var errMissing = errors.New("does not exist")

// readFile reads a regular file (never through a symlink), at most max bytes. A missing file is nil, nil.
func (t *tree) readFile(rel string, maxBytes int64) ([]byte, error) {
	fi, err := t.lstat(rel)
	if err != nil || fi == nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, unsafePath(rel, "not a regular file")
	}
	if fi.Size() > maxBytes {
		return nil, unsafePath(rel, "larger than expected")
	}
	f, err := t.root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !os.SameFile(st, fi) {
		return nil, unsafePath(rel, "replaced while being read")
	}
	return io.ReadAll(io.LimitReader(f, maxBytes+1))
}

// writeFile makes rel a regular file with exactly content and owner o, atomically: a temporary file in the same
// directory (O_EXCL), fchown/fchmod, fsync, rename over rel, fsync of the directory. Nothing is written when the file
// already has that content (owner and mode are corrected in place). A symlink or a directory at rel is refused.
func (t *tree) writeFile(rel string, content []byte, o owner) (bool, error) {
	fi, err := t.lstat(rel)
	if err != nil {
		return false, err
	}
	if fi != nil {
		if !fi.Mode().IsRegular() {
			return false, unsafePath(rel, "not a regular file")
		}
		if fi.Size() == int64(len(content)) {
			cur, err := t.readFile(rel, int64(len(content)))
			if err != nil {
				return false, err
			}
			if bytes.Equal(cur, content) {
				return t.fix(rel, fi, o)
			}
		}
	}
	dir := filepath.Dir(rel)
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return false, err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(rel)+".tmp-"+hex.EncodeToString(rnd[:]))
	f, err := t.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, fmt.Errorf("create %s: %w", filepath.ToSlash(tmp), err)
	}
	done := false
	defer func() {
		if !done {
			_ = f.Close()
			_ = t.root.Remove(tmp)
		}
	}()
	if _, err := f.Write(content); err != nil {
		return false, err
	}
	if err := f.Chown(o.uid, o.gid); err != nil {
		return false, fmt.Errorf("chown %s: %w", filepath.ToSlash(rel), err)
	}
	if err := f.Chmod(o.mode); err != nil {
		return false, err
	}
	if err := f.Sync(); err != nil {
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	if err := t.root.Rename(tmp, rel); err != nil {
		_ = t.root.Remove(tmp)
		done = true
		return false, fmt.Errorf("rename %s: %w", filepath.ToSlash(rel), err)
	}
	done = true
	return true, t.syncDir(dir)
}

// ensureFileOwner corrects owner and mode of an existing regular file.
func (t *tree) ensureFileOwner(rel string, o owner) error {
	fi, err := t.lstat(rel)
	if err != nil {
		return err
	}
	if fi == nil {
		return fmt.Errorf("%s: %w", filepath.ToSlash(rel), errMissing)
	}
	if !fi.Mode().IsRegular() {
		return unsafePath(rel, "not a regular file")
	}
	_, err = t.fix(rel, fi, o)
	return err
}

func (t *tree) syncDir(rel string) error {
	d, err := t.root.Open(rel)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// ---------------------------------------------------------------------------------------------------- instance layout

// layout is the relative paths of one instance under the tenants directory.
type layout struct {
	id                                                string
	dir, config, records, data, meta                  string
	composeFile, configFile, policyFile, recordsFile  string
	metaFile, activatedFile, creatingDir, removingDir string
}

func newLayout(id string) layout {
	return layout{
		id: id, dir: id,
		config: filepath.Join(id, "config"), records: filepath.Join(id, "records"),
		data: filepath.Join(id, "data"), meta: filepath.Join(id, "meta"),
		composeFile: filepath.Join(id, "compose.yaml"), configFile: filepath.Join(id, "config", "config.yaml"),
		policyFile: filepath.Join(id, "config", "bootstrap-policy.hujson"), recordsFile: filepath.Join(id, "records", "extra-records.json"),
		metaFile: filepath.Join(id, "meta", "instance.json"), activatedFile: filepath.Join(id, "meta", "activated"),
		// hidden, non-UUID names: the guard and ListInstances ignore them
		creatingDir: "." + id + ".creating", removingDir: "." + id + ".removing",
	}
}

func (l layout) under(base string) layout {
	r := newLayout(l.id)
	for _, p := range []*string{&r.dir, &r.config, &r.records, &r.data, &r.meta, &r.composeFile, &r.configFile, &r.policyFile,
		&r.recordsFile, &r.metaFile, &r.activatedFile} {
		rel, _ := filepath.Rel(l.id, *p)
		*p = filepath.Join(base, rel)
	}
	return r
}

// owners of the paths of one instance.
func (t *tree) owners(runUID int) map[string]owner {
	return map[string]owner{
		"dir":     {t.agentUID, runUID, modeInstanceDir},
		"config":  {t.agentUID, runUID, modeConfigDir},
		"records": {t.agentUID, runUID, modeConfigDir},
		"meta":    {t.agentUID, t.agentGID, modeMetaDir},
		"data":    {runUID, runUID, modeDataDir},
		"tenant":  {t.agentUID, runUID, modeTenantFile},
		"compose": {t.agentUID, t.agentGID, modeCompose},
		"metaf":   {t.agentUID, t.agentGID, modeMeta},
	}
}

// createInstance assembles a new instance directory under a hidden name — meta/instance.json first, then config/,
// records/, data/ — and renames it into place: the guard never sees an instance directory without its meta, even
// after a crash (a leftover hidden directory is removed by the next attempt).
func (t *tree) createInstance(l layout, runUID int, meta []byte) (err error) {
	o := t.owners(runUID)
	if err := t.removeAll(l.creatingDir); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = t.removeAll(l.creatingDir)
		}
	}()
	c := l.under(l.creatingDir)
	steps := []struct {
		rel string
		o   owner
	}{{c.dir, o["dir"]}, {c.meta, o["meta"]}}
	for _, s := range steps {
		if _, err := t.ensureDir(s.rel, s.o, true); err != nil {
			return err
		}
	}
	if _, err := t.writeFile(c.metaFile, meta, o["metaf"]); err != nil {
		return err
	}
	for _, s := range []struct {
		rel string
		o   owner
	}{{c.config, o["config"]}, {c.records, o["records"]}, {c.data, o["data"]}} {
		if _, err := t.ensureDir(s.rel, s.o, true); err != nil {
			return err
		}
	}
	if err := t.syncDir(c.dir); err != nil {
		return err
	}
	if fi, err := t.lstat(l.dir); err != nil || fi != nil {
		return errors.Join(err, unsafePath(l.dir, "appeared while the instance was being created"))
	}
	if err := t.root.Rename(c.dir, l.dir); err != nil {
		return fmt.Errorf("rename the new instance directory into place: %w", err)
	}
	return t.syncDir(".")
}

// removeFile removes the regular file rel (absent is not an error; anything else than a regular file is refused) and
// syncs its directory.
func (t *tree) removeFile(rel string) error {
	fi, err := t.lstat(rel)
	if err != nil || fi == nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return unsafePath(rel, "not a regular file")
	}
	if err := t.root.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", filepath.ToSlash(rel), err)
	}
	return t.syncDir(filepath.Dir(rel))
}

// removeAll removes rel and everything below it without following any symlink (os.Root). Absent is not an error.
func (t *tree) removeAll(rel string) error {
	if err := t.root.RemoveAll(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", filepath.ToSlash(rel), err)
	}
	return nil
}

// removeInstance renames the instance directory to a hidden name first — the guard then sees no half-removed
// instance — and removes it. A leftover of an interrupted removal is removed too.
func (t *tree) removeInstance(l layout) (bool, error) {
	fi, err := t.lstat(l.dir)
	if err != nil {
		return false, err
	}
	removed := false
	if fi != nil {
		if !fi.IsDir() {
			return false, unsafePath(l.dir, "not a directory")
		}
		if err := t.removeAll(l.removingDir); err != nil {
			return false, err
		}
		if err := t.root.Rename(l.dir, l.removingDir); err != nil {
			return false, fmt.Errorf("rename the instance directory away: %w", err)
		}
		if err := t.syncDir("."); err != nil {
			return false, err
		}
		removed = true
	}
	return removed, t.removeAll(l.removingDir)
}
