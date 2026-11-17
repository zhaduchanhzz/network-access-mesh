//go:build !linux

package compose

import "io/fs"

// identity: no ctime here — nothing is cached, the helper runs every time.
func identity(fs.FileInfo) fileID { return fileID{} }
