//go:build !unix

package compose

import "io/fs"

// The Host Agent runs on Linux only; elsewhere the driver compiles but no path has a known owner (every check fails).
func fileOwner(fs.FileInfo) (int, int, bool) { return 0, 0, false }
