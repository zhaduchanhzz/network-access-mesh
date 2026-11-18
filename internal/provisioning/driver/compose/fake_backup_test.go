//go:build linux

package compose

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

// validDB is the smallest file the data-check helper accepts: one 4096-byte page starting with a valid SQLite header.
func validDB() []byte {
	b := make([]byte, 4096)
	copy(b, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(b[16:18], 4096)
	return b
}

// fakeAge stands for age in the unit tests (the real binary runs in agent-it): the "ciphertext" names its
// recipients, and only an identity whose public key is one of them "decrypts" it.
const fakeAgeMagic = "FAKE-AGE\n"

func helperResult(r HelperResult, code int) (OneShotResult, error) {
	r.OK = code == 0
	b, _ := json.Marshal(r)
	return OneShotResult{ExitCode: code, Stdout: append(b, '\n')}, nil
}

// backupHelper plays the three helper subcommands with the agent's own code wherever no binary is needed: the
// inventory of data/ (IT-15), the tar writer and reader, the data-check; sqlite3 and age are simulated.
func (f *fakeEngine) backupHelper(s OneShot, src map[string]string) (OneShotResult, error) {
	env := helperEnv{dataDir: src[helperDataDir], staging: src[helperStagingDir], now: time.Now}
	switch s.Cmd[0] {
	case DataCheckCommand:
		o := env.dataCheck(DefaultMaxDBBytes)
		return helperResult(o.res, o.code)
	case BackupSnapshotCommand:
		var req BackupHelperRequest
		if err := json.Unmarshal(s.Stdin, &req); err != nil {
			return helperResult(HelperResult{Problem: "error"}, 1)
		}
		if _, o := env.inventory(req.MaxDBBytes); o != nil {
			return helperResult(o.res, o.code)
		}
		read := func(p string) []byte { b, _ := os.ReadFile(p); return b } //nolint:gosec // a temporary directory of the test
		db := read(filepath.Join(env.dataDir, "db.sqlite"))
		if !bytes.HasPrefix(db, []byte("SQLite format 3\x00")) {
			return helperResult(HelperResult{Problem: "integrity", Reason: "integrity_check failed on the database copy", Path: backupfmt.PathDB}, HelperExitIntegrity)
		}
		noise := read(filepath.Join(env.dataDir, "noise_private.key"))
		fp, err := NoiseFingerprint(noise)
		if err != nil {
			return helperResult(HelperResult{Problem: "integrity", Path: backupfmt.PathNoiseKey}, HelperExitIntegrity)
		}
		derp := read(filepath.Join(env.dataDir, "derp_server_private.key"))
		cfg := read(filepath.Join(src["/etc/headscale"], "config.yaml"))
		recs := read(filepath.Join(src["/etc/headscale-records"], "extra-records.json"))
		var tarball bytes.Buffer
		files, err := writeTar(&tarball, []tarSource{
			{backupfmt.PathDB, bytes.NewReader(db), int64(len(db))},
			{backupfmt.PathNoiseKey, bytes.NewReader(noise), int64(len(noise))},
			{backupfmt.PathDERPKey, bytes.NewReader(derp), int64(len(derp))},
			{backupfmt.PathConfig, bytes.NewReader(cfg), int64(len(cfg))},
			{backupfmt.PathRecords, bytes.NewReader(recs), int64(len(recs))},
		}, time.Now())
		if err != nil {
			return helperResult(HelperResult{Problem: "error"}, 1)
		}
		out := append([]byte(fakeAgeMagic+strings.Join(req.Recipients, "\n")+"\n--\n"), tarball.Bytes()...)
		if err := os.WriteFile(filepath.Join(env.staging, stagingArchive), out, 0o600); err != nil {
			return helperResult(HelperResult{Problem: "error"}, 1)
		}
		chownAs(s, filepath.Join(env.staging, stagingArchive))
		return helperResult(HelperResult{Files: files, NoiseFingerprint: fp, SQLiteVersion: "3.54.1", ArchiveSize: int64(len(out))}, 0)
	case RestoreUnpackCommand:
		var req RestoreHelperRequest
		if err := json.Unmarshal(s.Stdin, &req); err != nil {
			return helperResult(HelperResult{Problem: "error"}, 1)
		}
		raw, err := os.ReadFile(src[helperArchiveIn])
		if err != nil {
			return helperResult(HelperResult{Problem: "error"}, 1)
		}
		head, body, ok := bytes.Cut(raw, []byte("\n--\n"))
		key, kerr := backupfmt.ParseAgeIdentity(req.Identity)
		pub, perr := backupfmt.DataRecipient(key)
		rcp, rerr := backupfmt.RecipientString(pub)
		if !ok || !bytes.HasPrefix(head, []byte(fakeAgeMagic)) || kerr != nil || perr != nil || rerr != nil ||
			!slices.Contains(strings.Split(string(head[len(fakeAgeMagic):]), "\n"), rcp) {
			return helperResult(HelperResult{Problem: "integrity", Reason: "the archive does not decrypt with this data key"}, HelperExitIntegrity)
		}
		want := map[string]backupfmt.File{}
		for _, f := range req.Files {
			want[f.Path] = f
		}
		dst := filepath.Join(env.staging, stagingData)
		if err := os.Mkdir(dst, 0o700); err != nil {
			return helperResult(HelperResult{Problem: "error"}, 1)
		}
		files, o := unpackTar(bytes.NewReader(body), want, dst, req.MaxDBBytes)
		if o != nil {
			_ = os.RemoveAll(dst)
			return helperResult(o.res, o.code)
		}
		for _, n := range []string{"", "db.sqlite", "noise_private.key", "derp_server_private.key"} {
			chownAs(s, filepath.Join(dst, n))
		}
		noise, _ := os.ReadFile(filepath.Join(dst, "noise_private.key")) //nolint:gosec // a temporary directory of the test
		fp, err := NoiseFingerprint(noise)
		if err != nil {
			return helperResult(HelperResult{Problem: "integrity"}, HelperExitIntegrity)
		}
		return helperResult(HelperResult{Files: files, NoiseFingerprint: fp}, 0)
	}
	return helperResult(HelperResult{Problem: "error", Reason: "unknown helper"}, 1)
}

// offlinePolicy plays `headscale policy set --bypass-grpc-and-access-database-directly --force --file …` on the
// restored data directory: it records the policy file it was given.
func (f *fakeEngine) offlinePolicy(s OneShot, src map[string]string) (OneShotResult, error) {
	if !slices.Contains(s.Cmd, "--bypass-grpc-and-access-database-directly") || !slices.Contains(s.Cmd, "--force") {
		return OneShotResult{ExitCode: 1, Stderr: []byte("interactive confirmation required")}, nil
	}
	raw, err := os.ReadFile(filepath.Join(src["/etc/headscale"], restorePolicyFile))
	if err != nil {
		return OneShotResult{ExitCode: 1, Stderr: []byte("reading the policy file")}, nil
	}
	if _, err := os.Stat(filepath.Join(src["/var/lib/headscale"], "db.sqlite")); err != nil {
		return OneShotResult{ExitCode: 1, Stderr: []byte("no database")}, nil
	}
	f.mu.Lock()
	f.offline = append(f.offline, raw)
	f.mu.Unlock()
	return OneShotResult{Stdout: []byte("Policy updated.\n")}, nil
}

// chownAs gives a file the owner the helper container runs as (the real helper writes as run_uid).
func chownAs(s OneShot, p string) {
	uid, _ := strconv.Atoi(strings.Split(s.User, ":")[0])
	_ = os.Lchown(p, uid, uid)
}
