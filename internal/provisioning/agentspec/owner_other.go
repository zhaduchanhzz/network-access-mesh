//go:build !unix

package agentspec

import "io/fs"

// fileOwner cannot be known here: the agent runs on Linux only, so ownership checks fail closed elsewhere.
func fileOwner(fs.FileInfo) (int, bool) { return 0, false }
