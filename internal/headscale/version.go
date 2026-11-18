package headscale

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a Headscale release version as reported by GET /version ("v0.29.7").
type Version struct {
	Major, Minor, Patch int
	Raw                 string
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

func (v Version) less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}

// ParseVersion parses "v0.29.7" / "0.29.7". Pre-release, build metadata and "-dirty" builds are rejected: only
// release images pinned in versions.lock are supported.
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	parts := strings.Split(strings.TrimPrefix(raw, "v"), ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("not a release version: %q", raw)
	}
	var n [3]int
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil || x < 0 || strconv.Itoa(x) != p {
			return Version{}, fmt.Errorf("not a release version: %q", raw)
		}
		n[i] = x
	}
	return Version{Major: n[0], Minor: n[1], Patch: n[2], Raw: raw}, nil
}

// apiImpl is one implementation of Instance for a range of Headscale versions (the version layer — RT-11: 0.30
// removes gRPC, replaces REST v1 with OpenAPI 3.1 + RFC 7807 errors and adds API v2, so it gets its own entry).
type apiImpl struct {
	name      string
	min       Version // inclusive
	below     Version // exclusive
	construct func(c *conn) Instance
}

// apiImpls lists the supported ranges. 0.29.7 is the floor: earlier 0.29 patches keep expired nodes online and
// deleted nodes connected (ID-09).
var apiImpls = []apiImpl{
	{name: "rest-v1/0.29", min: Version{Major: 0, Minor: 29, Patch: 7}, below: Version{Major: 0, Minor: 30, Patch: 0},
		construct: func(c *conn) Instance { return &v029{c: c} }},
}

// SupportedVersions describes the supported range, for messages and the evidence.
func SupportedVersions() string {
	var b strings.Builder
	for i, impl := range apiImpls {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, ">= %s, < %s", impl.min, impl.below)
	}
	return b.String()
}

// CheckSupported parses a version as GET /version reports it and checks that the adapter has an implementation for it
// — the "contract test of the adapter green for the target version" precondition of an upgrade (§11.4, P3-T13a): a
// version outside SupportedVersions is never upgraded to.
func CheckSupported(raw string) (Version, error) {
	v, err := ParseVersion(raw)
	if err != nil {
		return Version{}, err
	}
	if _, ok := implFor(v); !ok {
		return v, fmt.Errorf("%s is outside the adapter's supported versions (%s)", v.Raw, SupportedVersions())
	}
	return v, nil
}

func implFor(v Version) (apiImpl, bool) {
	for _, impl := range apiImpls {
		if !v.less(impl.min) && v.less(impl.below) {
			return impl, true
		}
	}
	return apiImpl{}, false
}
