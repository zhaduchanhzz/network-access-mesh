// Package buildinfo carries the version and commit stamped at build time (-ldflags -X).
package buildinfo

var (
	// Version is the release version, e.g. "0.1.0"; "dev" for local builds.
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
)
