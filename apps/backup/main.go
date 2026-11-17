// Command meshguard-backup is the scheduled, encrypted backup service of the platform (P2-T03a, P2-T05b; §14.4,
// §17.1 of the master plan). One container per target, all from the same image:
//
//	postgres  pg_dump of the Management Plane database as mg_backup (BYPASSRLS, read-only) + the cluster globals
//	idp       pg_dump of the Keycloak database as idp_backup (read-only) + the globals of idp-db
//	edge      a tar archive of the edge's ACME volume (mounted read-only)
//
// Every artifact is encrypted to the platform recovery public key (age X25519, MG_BACKUP_RECIPIENT) while it is being
// produced: the plaintext only flows through a pipe (pg_dump → age, or the tar writer → age), and only age's output
// is written, so no plaintext backup ever touches a disk. A missing or invalid recipient stops the process before
// anything is written. Each run writes a manifest and the status file (time, sha256, size) that the overdue-backup
// alert reads (§16.3), then applies the retention.
//
// Subcommands (exit status 0 = ok, 1 = the backup failed, 2 = configuration error — nothing written):
//
//	meshguard-backup [run]                       the daemon: one backup a day at MG_BACKUP_DAILY_AT (UTC)
//	meshguard-backup once [--label L]            one backup now (pre-migration: --label pre-migration), then exit
//	meshguard-backup check                       validate the configuration and the recipient; writes nothing
//	meshguard-backup status [--max-age D]        print the status file; exit 1 when the last success is too old
//	meshguard-backup version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

const usage = `usage: meshguard-backup [run]
       meshguard-backup once [--label pre-migration|manual]
       meshguard-backup check
       meshguard-backup status [--max-age <duration>]
       meshguard-backup version
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := dispatch(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// dispatch runs one subcommand and returns the exit status. Arguments are never echoed back (a value that must stay
// secret could have been passed by mistake).
func dispatch(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	cmd := "run"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "version":
		_, _ = fmt.Fprintf(stdout, "meshguard-backup %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		return 0
	case "run", "once", "check", "status":
	default:
		_, _ = fmt.Fprint(stderr, "meshguard-backup: unknown subcommand\n"+usage)
		return 2
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	label := fs.String("label", LabelManual, "")
	maxAge := fs.Duration("max-age", 0, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 ||
		(cmd != "once" && isSet(fs, "label")) || (cmd != "status" && isSet(fs, "max-age")) {
		_, _ = fmt.Fprint(stderr, "meshguard-backup: invalid arguments\n"+usage)
		return 2
	}
	cfg, err := LoadConfig(getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-backup %s: invalid configuration — nothing written:\n%v\n", cmd, err)
		return 2
	}
	log := logx.New(stdout, cfg.LogLevel, "backup").With("target", cfg.Target)
	switch cmd {
	case "status":
		return statusCmd(cfg, *maxAge, stdout, stderr)
	case "check":
		return checkCmd(ctx, cfg, log)
	case "once":
		if *label != LabelManual && *label != LabelPreMigration {
			_, _ = fmt.Fprint(stderr, "meshguard-backup once: --label must be pre-migration or manual\n")
			return 2
		}
		return onceCmd(ctx, cfg, log, *label)
	default:
		return daemon(ctx, cfg, log)
	}
}

func isSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// checkCmd validates everything a run needs, without writing anything.
func checkCmd(ctx context.Context, cfg *Config, log *slog.Logger) int {
	tools, err := cfg.Preflight(ctx)
	if err != nil {
		log.Error("check failed — nothing written", "err", err)
		return 2
	}
	log.Info("check passed", "recipient", cfg.Recipient, "tools", tools, "dest", cfg.Dest, "daily_at_utc", cfg.DailyAtString())
	return 0
}

// onceCmd runs one backup now (the pre-migration trigger of P2-T03a: `once --label pre-migration`).
func onceCmd(ctx context.Context, cfg *Config, log *slog.Logger, label string) int {
	tools, err := cfg.Preflight(ctx)
	if err != nil {
		log.Error("refusing to run — nothing written", "err", err)
		return 2
	}
	b := &Backuper{Cfg: cfg, Log: log, Tools: tools, Now: time.Now}
	m, err := b.Run(ctx, label)
	switch {
	case errors.Is(err, ErrConfig):
		log.Error("refusing to run — nothing written", "err", err)
		return 2
	case err != nil:
		log.Error("backup failed", "label", label, "err", err)
		return 1
	}
	log.Info("backup done", "id", m.ID, "label", label, "files", len(m.Files), "bytes", m.TotalBytes())
	return 0
}

// statusCmd prints the status file and reports whether the last success is recent enough.
func statusCmd(cfg *Config, maxAge time.Duration, stdout, stderr io.Writer) int {
	if maxAge <= 0 {
		maxAge = cfg.MaxAge
	}
	raw, st, err := ReadStatus(cfg.Dest)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-backup status: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(raw)
	if st.LastSuccess == nil || time.Since(st.LastSuccess.FinishedAt) > maxAge {
		_, _ = fmt.Fprintf(stderr, "meshguard-backup status: no successful backup in the last %s\n", maxAge)
		return 1
	}
	return 0
}
