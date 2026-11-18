package compose

import (
	"encoding/json"
	"io"
	"regexp"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

// The backup helpers (P3-T11, §17.1–§17.2) are subcommands of the agent binary run by the agent in a one-shot
// container of its own image — the tenant's run_uid, network none, read-only rootfs, cap_drop ALL, no-new-privileges,
// a memory/CPU/PID limit and a hard timeout — so that the agent process (root) never reads, parses or decrypts a byte
// a tenant process could have written:
//
//	meshguard-agent backup-snapshot   data/ read-only at /var/lib/headscale, config/ and records/ read-only, the job's
//	                                  staging directory at /staging; stdin: BackupHelperRequest (no secret — public
//	                                  recipients only); writes /staging/archive.tar.age
//	meshguard-agent restore-unpack    the archive read-only at /in/archive.tar.age, the staging directory at /staging;
//	                                  stdin: RestoreHelperRequest (the data key's identity — a secret, never on disk);
//	                                  writes /staging/data/
//	meshguard-agent data-check        data/ read-only: the start guard's structural check of the database file
//
// Each prints one HelperResult (JSON) on stdout. Exit status: 0 ok, HelperExitUnsafe (a hostile data directory or
// archive entry: symlink, FIFO, device, socket, hard link, oversized or unexpected file), HelperExitIntegrity (a corrupt
// database, a decryption or hash failure), 1 any other error.

// Subcommands.
const (
	BackupSnapshotCommand = "backup-snapshot"
	RestoreUnpackCommand  = "restore-unpack"
	DataCheckCommand      = "data-check"
)

// Exit codes of the helpers.
const (
	HelperExitUnsafe    = 5
	HelperExitIntegrity = 6
)

// Fixed paths inside a helper container.
const (
	helperDataDir     = "/var/lib/headscale"
	helperConfigFile  = "/etc/headscale/config.yaml"
	helperRecordsFile = "/etc/headscale-records/extra-records.json"
	helperStagingDir  = "/staging"
	helperArchiveIn   = "/in/archive.tar.age"
	// binaries of the agent image (infrastructure/docker/agent/Dockerfile; versions.lock [sources.sqlite], [sources.age])
	SQLiteBinary = "/usr/local/bin/sqlite3"
	AgeBinary    = "/usr/local/bin/age"
	// stagingArchive is the archive the backup helper writes, relative to the staging directory.
	stagingArchive = "archive.tar.age"
	// stagingData is the data directory the restore helper writes, relative to the staging directory.
	stagingData = "data"
)

// Size bounds of data/ (§17.1 "có trần kích thước từng file và tổng"). The database bound comes from the agent's
// configuration (MG_AGENT_BACKUP_MAX_DB_BYTES).
const (
	maxKeyFileBytes = 4 << 10
	maxShmBytes     = 64 << 20
	maxConfigBytes  = 1 << 20
	// DefaultMaxDBBytes bounds db.sqlite (and its -wal) when the agent's configuration does not.
	DefaultMaxDBBytes = 2 << 30
)

// BackupHelperRequest is the stdin of backup-snapshot.
type BackupHelperRequest struct {
	Method string `json:"method"` // backupfmt.MethodVacuumInto | MethodColdCopy
	// Recipients are age X25519 recipients (the data key's and the recovery one) — public values.
	Recipients []string `json:"recipients"`
	MaxDBBytes int64    `json:"max_db_bytes"`
}

// RestoreHelperRequest is the stdin of restore-unpack.
type RestoreHelperRequest struct {
	// Identity is the data key as age encodes it (AGE-SECRET-KEY-1…): a secret, only ever on this pipe.
	Identity   string           `json:"identity"`
	Files      []backupfmt.File `json:"files"`
	MaxDBBytes int64            `json:"max_db_bytes"`
}

// HelperResult is the stdout of every helper.
type HelperResult struct {
	OK bool `json:"ok"`
	// Problem: "unsafe" | "integrity" | "error" when not OK; Reason is a fixed text, Path an entry of data/ or of the
	// archive (only names of the allowlist, or "(unexpected name)").
	Problem          string           `json:"problem,omitempty"`
	Reason           string           `json:"reason,omitempty"`
	Path             string           `json:"path,omitempty"`
	Files            []backupfmt.File `json:"files,omitempty"`
	NoiseFingerprint string           `json:"noise_key_fingerprint,omitempty"`
	SQLiteVersion    string           `json:"sqlite_version,omitempty"`
	ArchiveSize      int64            `json:"archive_size,omitempty"`
}

// dataEntries are the only names data/ may hold, with their size bounds (0: the database bound).
var dataEntries = map[string]int64{
	"db.sqlite":               0,
	"db.sqlite-wal":           0,
	"db.sqlite-shm":           maxShmBytes,
	"noise_private.key":       noiseKeyMaxBytes,
	"derp_server_private.key": maxKeyFileBytes,
}

var safeNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// reportedName is how a name of data/ appears in a result: a tenant chooses it, so only a plain short name is echoed.
func reportedName(name string) string {
	if safeNameRE.MatchString(name) {
		return name
	}
	return "(unexpected name)"
}

func writeResult(w io.Writer, r HelperResult) {
	b, err := json.Marshal(r)
	if err != nil {
		b = []byte(`{"ok":false,"problem":"error","reason":"result encoding"}`)
	}
	_, _ = w.Write(append(b, '\n'))
}

// helperOutcome is how a helper ends: the result and the exit code.
type helperOutcome struct {
	res  HelperResult
	code int
}

func unsafeOutcome(reason, path string) helperOutcome {
	return helperOutcome{HelperResult{Problem: "unsafe", Reason: reason, Path: path}, HelperExitUnsafe}
}

func integrityOutcome(reason, path string) helperOutcome {
	return helperOutcome{HelperResult{Problem: "integrity", Reason: reason, Path: path}, HelperExitIntegrity}
}

func errorOutcome(reason string) helperOutcome {
	return helperOutcome{HelperResult{Problem: "error", Reason: reason}, 1}
}

// RunHelper runs one helper subcommand (apps/agent dispatch).
func RunHelper(cmd string, stdin io.Reader, stdout io.Writer) int {
	env := defaultHelperEnv()
	var o helperOutcome
	switch cmd {
	case BackupSnapshotCommand:
		var req BackupHelperRequest
		if err := decodeHelperRequest(stdin, &req); err != nil {
			o = errorOutcome("request: " + err.Error())
			break
		}
		o = env.backupSnapshot(req)
	case RestoreUnpackCommand:
		var req RestoreHelperRequest
		err := decodeHelperRequest(stdin, &req)
		if err != nil {
			o = errorOutcome("request: " + err.Error())
			break
		}
		o = env.restoreUnpack(req)
		clearString(&req.Identity)
	case DataCheckCommand:
		o = env.dataCheck(DefaultMaxDBBytes)
	default:
		o = errorOutcome("unknown helper")
	}
	o.res.OK = o.code == 0
	writeResult(stdout, o.res)
	return o.code
}

func decodeHelperRequest(r io.Reader, v any) error {
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// clearString drops the reference to a secret string (Go strings are immutable: the best a helper can do is to let the
// process — which ends right after — forget it).
func clearString(s *string) { *s = "" }
