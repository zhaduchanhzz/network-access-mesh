package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Targets and their kind: a PostgreSQL database (pg_dumpall --globals-only + pg_dump) or a directory (tar).
const (
	TargetPostgres = "postgres"
	TargetIdP      = "idp"
	TargetEdge     = "edge"
)

// Labels of a backup set: the daemon's daily run, the run before a migration, an operator's run.
const (
	LabelScheduled    = "scheduled"
	LabelPreMigration = "pre-migration"
	LabelManual       = "manual"
)

// ErrConfig marks a configuration problem (recipient, tools, paths): the run stops before writing anything.
var ErrConfig = errors.New("configuration")

// Config is the whole configuration, from environment variables only. None of them holds a secret: the database
// password is a file (Docker secret), the recipient is a public key.
type Config struct {
	Target        string
	Dest          string // directory the artifacts, manifests and the status file are written to
	Recipient     string // age X25519 recipient (age1…) — the platform recovery public key (§17.1)
	RecipientFile string // optional: the host's recipient file (key ceremony output); must hold the same recipient
	DailyAt       time.Duration
	RetryAfter    time.Duration
	Timeout       time.Duration
	MaxAge        time.Duration // a status older than this is overdue (status subcommand; hint for the alert)
	KeepDays      int
	KeepMin       int
	KeepOnDemand  int
	AgeBin        string
	PGBinDir      string
	RuntimeDir    string // tmpfs for the pgpass file of a run (removed after the run)
	Source        string // edge: the directory to archive (read-only mount)
	PG            PGConfig
	LogLevel      slog.Level
}

// PGConfig is how pg_dump reaches the database; the password is read from PasswordFile at every run.
type PGConfig struct {
	Host, Port, Database, User, PasswordFile, SSLMode string
}

// IsPG reports whether the target is a PostgreSQL database.
func (c *Config) IsPG() bool { return c.Target == TargetPostgres || c.Target == TargetIdP }

// DailyAtString renders DailyAt as HH:MM.
func (c *Config) DailyAtString() string {
	m := int(c.DailyAt / time.Minute)
	return fmt.Sprintf("%02d:%02d", m/60, m%60)
}

var (
	hostRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	identRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`) // database and role names used here: lower-case identifiers
	dailyRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)
)

// LoadConfig reads and validates the configuration. It does not touch the recipient file or run any tool
// (Preflight does).
func LoadConfig(getenv func(string) string) (*Config, error) {
	var errs []error
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	dur := func(k, def string) time.Duration {
		d, err := time.ParseDuration(get(k, def))
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s: a positive duration (e.g. 30m) is required", k))
		}
		return d
	}
	num := func(k string, def, lo int) int {
		n, err := strconv.Atoi(get(k, strconv.Itoa(def)))
		if err != nil || n < lo || n > 10000 {
			errs = append(errs, fmt.Errorf("%s: an integer in %d..10000 is required", k, lo))
		}
		return n
	}
	c := &Config{
		Target:        get("MG_BACKUP_TARGET", ""),
		Dest:          get("MG_BACKUP_DEST", "/backups"),
		Recipient:     strings.TrimSpace(getenv("MG_BACKUP_RECIPIENT")),
		RecipientFile: get("MG_BACKUP_RECIPIENT_FILE", ""),
		RetryAfter:    dur("MG_BACKUP_RETRY_AFTER", "30m"),
		Timeout:       dur("MG_BACKUP_TIMEOUT", "2h"),
		MaxAge:        dur("MG_BACKUP_MAX_AGE", "26h"),
		KeepDays:      num("MG_BACKUP_KEEP_DAYS", 14, 1),
		KeepMin:       num("MG_BACKUP_KEEP_MIN", 7, 1),
		KeepOnDemand:  num("MG_BACKUP_KEEP_ONDEMAND", 5, 1),
		AgeBin:        get("MG_BACKUP_AGE_BIN", "/usr/local/bin/age"),
		PGBinDir:      get("MG_BACKUP_PG_BIN_DIR", "/usr/local/bin"),
		RuntimeDir:    get("MG_BACKUP_RUNTIME_DIR", "/run/mgbackup"),
		Source:        get("MG_BACKUP_SOURCE", "/source"),
		PG: PGConfig{
			Host:         get("MG_BACKUP_PG_HOST", ""),
			Port:         get("MG_BACKUP_PG_PORT", "5432"),
			Database:     get("MG_BACKUP_PG_DATABASE", ""),
			User:         get("MG_BACKUP_PG_USER", ""),
			PasswordFile: get("MG_BACKUP_PG_PASSWORD_FILE", ""),
			SSLMode:      get("MG_BACKUP_PG_SSLMODE", "prefer"),
		},
	}
	switch c.Target {
	case TargetPostgres, TargetIdP, TargetEdge:
	default:
		errs = append(errs, errors.New("MG_BACKUP_TARGET: one of postgres, idp, edge is required"))
	}
	if err := ValidRecipient(c.Recipient); err != nil {
		errs = append(errs, fmt.Errorf("MG_BACKUP_RECIPIENT: %w", err))
	}
	if m := dailyRE.FindStringSubmatch(get("MG_BACKUP_DAILY_AT", "02:30")); m != nil {
		h, _ := strconv.Atoi(m[1])
		mi, _ := strconv.Atoi(m[2])
		c.DailyAt = time.Duration(h)*time.Hour + time.Duration(mi)*time.Minute
	} else {
		errs = append(errs, errors.New("MG_BACKUP_DAILY_AT: HH:MM (UTC) is required"))
	}
	for k, p := range map[string]string{"MG_BACKUP_DEST": c.Dest, "MG_BACKUP_AGE_BIN": c.AgeBin,
		"MG_BACKUP_PG_BIN_DIR": c.PGBinDir, "MG_BACKUP_RUNTIME_DIR": c.RuntimeDir, "MG_BACKUP_SOURCE": c.Source} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			errs = append(errs, fmt.Errorf("%s: a clean absolute path is required", k))
		}
	}
	if c.RecipientFile != "" && !filepath.IsAbs(c.RecipientFile) {
		errs = append(errs, errors.New("MG_BACKUP_RECIPIENT_FILE: an absolute path is required"))
	}
	if c.IsPG() {
		if !hostRE.MatchString(c.PG.Host) {
			errs = append(errs, errors.New("MG_BACKUP_PG_HOST: a host name is required"))
		}
		if p, err := strconv.Atoi(c.PG.Port); err != nil || p < 1 || p > 65535 {
			errs = append(errs, errors.New("MG_BACKUP_PG_PORT: a TCP port is required"))
		}
		if !identRE.MatchString(c.PG.Database) || !identRE.MatchString(c.PG.User) {
			errs = append(errs, errors.New("MG_BACKUP_PG_DATABASE and MG_BACKUP_PG_USER: lower-case identifiers are required"))
		}
		if !filepath.IsAbs(c.PG.PasswordFile) {
			errs = append(errs, errors.New("MG_BACKUP_PG_PASSWORD_FILE: an absolute path is required (Docker secret)"))
		}
		switch c.PG.SSLMode {
		case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		default:
			errs = append(errs, errors.New("MG_BACKUP_PG_SSLMODE: a libpq sslmode is required"))
		}
	} else if c.Dest == c.Source || strings.HasPrefix(c.Dest+"/", c.Source+"/") || strings.HasPrefix(c.Source+"/", c.Dest+"/") {
		errs = append(errs, errors.New("MG_BACKUP_SOURCE and MG_BACKUP_DEST must not overlap"))
	}
	lvl, err := logx.ParseLevel(get("MG_LOG_LEVEL", "info"))
	if err != nil {
		errs = append(errs, errors.New("MG_LOG_LEVEL: debug, info, warn or error"))
	}
	c.LogLevel = lvl
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// bech32 alphabet; an age X25519 recipient is "age1" + 58 characters (32-byte key + 6-character checksum).
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var recipientRE = regexp.MustCompile(`^age1[` + bech32Charset + `]{58}$`)

// ValidRecipient accepts exactly one age X25519 recipient with a valid bech32 checksum. Plugin recipients
// (age1<name>1…), several recipients, SSH keys and identities are refused; a private key pasted by mistake is never
// echoed back.
func ValidRecipient(s string) error {
	switch {
	case s == "":
		return errors.New("empty — the platform recovery recipient is not configured (key ceremony P2-T04a)")
	case strings.Contains(strings.ToUpper(s), "AGE-SECRET-KEY"):
		return errors.New("holds a private key, not a recipient — remove it from the configuration now")
	case !recipientRE.MatchString(s):
		return errors.New("not an age X25519 recipient (age1 followed by 58 bech32 characters)")
	case !bech32Valid("age", s[len("age1"):]):
		return errors.New("bech32 checksum mismatch — the recipient was mistyped")
	}
	return nil
}

func bech32Valid(hrp, data string) bool {
	values := make([]byte, 0, 2*len(hrp)+1+len(data))
	for _, c := range []byte(hrp) {
		values = append(values, c>>5)
	}
	values = append(values, 0)
	for _, c := range []byte(hrp) {
		values = append(values, c&31)
	}
	for _, c := range []byte(data) {
		i := strings.IndexByte(bech32Charset, c)
		if i < 0 {
			return false
		}
		values = append(values, byte(i)) //nolint:gosec // G115: index in a 32-character alphabet
	}
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range gen {
			if (top>>uint(i))&1 == 1 { //nolint:gosec // i < 5
				chk ^= gen[i]
			}
		}
	}
	return chk == 1
}

// recipientFromFile reads an age recipients file (the key ceremony writes a comment line and the recipient): blank
// lines and # comments are ignored, exactly one recipient must remain.
func recipientFromFile(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path from the service configuration (read-only bind mount)
	if err != nil {
		return "", fmt.Errorf("recipient file: %w", err)
	}
	if bytes.Contains(bytes.ToUpper(raw), []byte("AGE-SECRET-KEY")) {
		return "", errors.New("recipient file holds a private key — remove it from the host now")
	}
	var found []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		found = append(found, line)
	}
	if len(found) != 1 {
		return "", fmt.Errorf("recipient file must hold exactly one recipient, found %d", len(found))
	}
	if err := ValidRecipient(found[0]); err != nil {
		return "", fmt.Errorf("recipient file: %w", err)
	}
	return found[0], nil
}

// Tools are the versions of the external programs, recorded in every manifest.
type Tools map[string]string

// Preflight checks everything a run depends on, before anything is written: the recipient (and the host's recipient
// file, if configured, holds the same one), age accepts it, the tools run, the password file or the source directory
// is readable and the destination is a writable directory. Every failure wraps ErrConfig.
func (c *Config) Preflight(ctx context.Context) (Tools, error) {
	fail := func(format string, a ...any) (Tools, error) {
		return nil, fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, a...))
	}
	if err := ValidRecipient(c.Recipient); err != nil {
		return fail("MG_BACKUP_RECIPIENT: %v", err)
	}
	if c.RecipientFile != "" {
		r, err := recipientFromFile(c.RecipientFile)
		if err != nil {
			return fail("%v", err)
		}
		if r != c.Recipient {
			return fail("the host's recipient file and MG_BACKUP_RECIPIENT differ — re-render the compose from the env file")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// age parses the recipient exactly as it will during the run; encrypting nothing to the discard writer proves it.
	if _, err := runTool(ctx, c.AgeBin, nil, "--encrypt", "--recipient", c.Recipient); err != nil {
		return fail("age refuses the recipient or does not run: %v", err)
	}
	tools := Tools{}
	v, err := runTool(ctx, c.AgeBin, nil, "--version")
	if err != nil {
		return fail("age --version: %v", err)
	}
	tools["age"] = v
	if c.IsPG() {
		for _, t := range []string{"pg_dump", "pg_dumpall"} {
			v, err := runTool(ctx, filepath.Join(c.PGBinDir, t), nil, "--version")
			if err != nil {
				return fail("%s --version: %v", t, err)
			}
			tools[t] = v
		}
		if _, err := readPassword(c.PG.PasswordFile); err != nil {
			return fail("%v", err)
		}
		if err := writableDir(c.RuntimeDir); err != nil {
			return fail("MG_BACKUP_RUNTIME_DIR (tmpfs for the pgpass file): %v", err)
		}
	} else if fi, err := os.Stat(c.Source); err != nil || !fi.IsDir() {
		return fail("MG_BACKUP_SOURCE is not a readable directory")
	}
	if err := writableDir(c.Dest); err != nil {
		return fail("MG_BACKUP_DEST: %v", err)
	}
	return tools, nil
}

func writableDir(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("not a directory")
	}
	if err := syscall.Access(p, 0x2|0x1); err != nil { // W_OK|X_OK
		return fmt.Errorf("not writable by uid %d: %w", os.Getuid(), err)
	}
	return nil
}

// readPassword reads a one-line password file (Docker secret); the value is never logged.
func readPassword(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // Docker secret path from the configuration
	if err != nil {
		return "", fmt.Errorf("password file %s: %w", path, err)
	}
	pw := strings.TrimRight(string(raw), "\r\n")
	if pw == "" || strings.ContainsAny(pw, "\r\n\x00") {
		return "", fmt.Errorf("password file %s: one non-empty line is required", path)
	}
	return pw, nil
}

// runTool runs a short tool invocation with an empty environment and returns the first line of its output.
func runTool(ctx context.Context, bin string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: binary from the configuration, fixed arguments
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, firstLine(errb.String()))
	}
	return firstLine(out.String()), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return logx.RedactString(s)
}
