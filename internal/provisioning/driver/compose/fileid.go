package compose

import (
	"sync"

	"github.com/google/uuid"
)

// fileID is the identity of a file as lstat sees it — device, inode, size, mtime and ctime. A tenant process can
// change the content (mtime, ctime, size), replace the file (inode) or set its mtime back (ctime still moves), but it
// cannot produce the same identity with other content: an unchanged identity means an unchanged file, and the
// fingerprint computed for it still holds. ok is false where the platform gives no ctime (nothing is cached then).
type fileID struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
	ok           bool
}

// fpCache remembers the fingerprint helper's answer per instance and key-file identity, so that the start guard of
// every supervisor cycle (every activated instance, every 30 s) runs a helper container only when a key file changed
// — once per instance after the agent starts.
type fpCache struct {
	mu sync.Mutex
	m  map[uuid.UUID]fpEntry
}

type fpEntry struct {
	id fileID
	fp string
}

func (c *fpCache) get(id uuid.UUID, f fileID) (string, bool) {
	if !f.ok {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[id]
	if !ok || e.id != f {
		return "", false
	}
	return e.fp, true
}

func (c *fpCache) put(id uuid.UUID, f fileID, fp string) {
	if !f.ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[uuid.UUID]fpEntry{}
	}
	c.m[id] = fpEntry{id: f, fp: fp}
}

func (c *fpCache) forget(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, id)
}
