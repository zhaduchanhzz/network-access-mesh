package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

const kekDrillUsage = `usage: meshguard-worker kek-drill --live <dir> --recovered <dir> [--keyring kek-app,kek-ops]

Key ceremony drill (P2-T04a, docs/operations/key-ceremony.md). <live>/<keyring> is a live keyring directory,
<recovered>/<keyring> the same keyring rebuilt from its offline copies (absolute paths). The drill passes when, for
every keyring, both hold the same kek_ids with the same key check values (KCV), ACTIVE names the same kek_id, and a
DEK wrapped by one keyring unwraps with the other in both directions with the real AAD formats of the SecretStore,
decrypting a test secret; kek-app and kek-ops must not share a key. Output: kek_ids, KCVs and PASS/FAIL — never key
material. The ceremony runs it with --network none, read-only mounts and a non-root user.
Exit status: 0 PASS, 1 FAIL, 2 usage error.
`

// kekDrill is the kek-drill subcommand; it returns the exit status.
func kekDrill(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kek-drill", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors and usage are printed below, once
	live := fs.String("live", "", "")
	recovered := fs.String("recovered", "", "")
	keyrings := fs.String("keyring", secrets.KEKApp+","+secrets.KEKOps, "")
	usage := func(why string) int {
		_, _ = fmt.Fprintf(stderr, "kek-drill: %s\n%s", why, kekDrillUsage)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		return usage(err.Error()) // the flag package names the flag, never its value
	}
	names, err := parseKeyrings(*keyrings)
	switch {
	case err != nil:
		return usage(err.Error())
	case fs.NArg() != 0:
		return usage("unexpected arguments")
	case *live == "" || *recovered == "":
		return usage("--live and --recovered are required")
	case !filepath.IsAbs(*live) || !filepath.IsAbs(*recovered):
		return usage("--live and --recovered must be absolute paths")
	case filepath.Clean(*live) == filepath.Clean(*recovered):
		return usage("--recovered must not be the live directory (the drill would compare a keyring with itself)")
	}

	out := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, "kek-drill: "+format+"\n", a...) }
	out("process uid=%d gid=%d groups=%s network-interfaces=%s", os.Getuid(), os.Getgid(), groups(), interfaces())
	var (
		failures int
		kekIDs   int
		kcvOwner = map[string]string{} // KCV → keyring, to catch one key in both keyrings
	)
	for _, name := range names {
		r, err := secrets.Drill(name, filepath.Join(*live, name), filepath.Join(*recovered, name))
		if err != nil {
			out("%s: FAIL — %v", name, err) // LoadKeyring errors name files, never their content
			failures++
			continue
		}
		out("%s: ACTIVE live=%s recovered=%s", name, r.LiveActive, r.RecoveredActive)
		for _, k := range r.KEKs {
			out("%s: kek_id=%s kcv live=%s recovered=%s wrap live->recovered=%s recovered->live=%s", name, k.ID,
				orNone(k.LiveKCV), orNone(k.RecoveredKCV), verdict(k.LiveToRecovered), verdict(k.RecoveredToLive))
			for _, c := range slices.Compact([]string{k.LiveKCV, k.RecoveredKCV}) {
				if other, dup := kcvOwner[c]; c != "" && dup && other != name {
					r.Problems = append(r.Problems, fmt.Sprintf("%s and %s hold the same key (KCV %s) — each keyring "+
						"needs its own KEK (§7.6)", other, name, c))
				} else if c != "" {
					kcvOwner[c] = name
				}
			}
		}
		kekIDs += len(r.KEKs)
		if !r.OK() {
			for _, p := range r.Problems {
				out("%s: FAIL — %s", name, p)
			}
			failures += len(r.Problems)
			continue
		}
		out("%s: PASS", name)
	}
	if failures > 0 {
		out("FAIL (%d problems)", failures)
		return 1
	}
	out("PASS (%d keyrings, %d kek_ids)", len(names), kekIDs)
	return 0
}

// parseKeyrings reads the --keyring list: kek-app and/or kek-ops, each once.
func parseKeyrings(s string) ([]string, error) {
	var names []string
	for _, n := range strings.Split(s, ",") {
		n = strings.TrimSpace(n)
		if n != secrets.KEKApp && n != secrets.KEKOps {
			return nil, fmt.Errorf("--keyring takes %s and/or %s, comma-separated", secrets.KEKApp, secrets.KEKOps)
		}
		if slices.Contains(names, n) {
			return nil, fmt.Errorf("--keyring names %s twice", n)
		}
		names = append(names, n)
	}
	return names, nil
}

func verdict(ok bool) string {
	if ok {
		return "ok"
	}
	return "FAIL"
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// groups lists the supplementary group IDs of the process (evidence that the drill ran with the keyring groups only).
func groups() string {
	gs, err := os.Getgroups()
	if err != nil {
		return "?"
	}
	if len(gs) == 0 {
		return "(none)"
	}
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = strconv.Itoa(g)
	}
	return strings.Join(out, ",")
}

// interfaces lists the network interfaces the process sees ("lo" only under docker run --network none).
func interfaces() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return "?"
	}
	names := make([]string, 0, len(ifs))
	for _, i := range ifs {
		names = append(names, i.Name)
	}
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ",")
}
