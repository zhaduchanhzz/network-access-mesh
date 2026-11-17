package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Artifact parts of a backup set (file name = <set id>.<part>).
const (
	PartGlobals  = "globals.sql.age" // pg_dumpall --globals-only --no-role-passwords (roles, memberships, role settings)
	PartPGDump   = "pgdump.age"      // pg_dump --format=custom of the database
	PartTar      = "tar.age"         // tar of the source directory (numeric owners, modes, mtimes)
	PartManifest = "manifest.json"   // plaintext metadata, written last: a set without it is incomplete
)

// ManifestFormat identifies the manifest layout.
const ManifestFormat = "meshguard-backup/v1"

// FileEntry describes one encrypted artifact as written to disk (sha256 and size of the ciphertext).
type FileEntry struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// Manifest is the plaintext description of a complete backup set. It holds no secret.
type Manifest struct {
	Format     string      `json:"format"`
	ID         string      `json:"id"`
	Target     string      `json:"target"`
	Label      string      `json:"label"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
	Recipient  string      `json:"recipient"`
	Source     string      `json:"source"`
	Tools      Tools       `json:"tools"`
	Files      []FileEntry `json:"files"`
}

// TotalBytes is the summed size of the encrypted artifacts.
func (m *Manifest) TotalBytes() int64 {
	var n int64
	for _, f := range m.Files {
		n += f.Size
	}
	return n
}

// Backuper runs backup sets for one target.
type Backuper struct {
	Cfg   *Config
	Log   *slog.Logger
	Tools Tools
	Now   func() time.Time
}

// Run produces one backup set: lock the destination, encrypt every artifact while it is produced, write the
// manifest, update the status file, apply the retention. A configuration error (ErrConfig) is returned before
// anything is written; any other failure removes what this run wrote and records the failure in the status file.
func (b *Backuper) Run(ctx context.Context, label string) (*Manifest, error) {
	c := b.Cfg
	if err := ValidRecipient(c.Recipient); err != nil { // Preflight ran at start-up; never encrypt to a bad recipient
		return nil, fmt.Errorf("%w: MG_BACKUP_RECIPIENT: %w", ErrConfig, err)
	}
	if c.RecipientFile != "" { // the host's file may have changed since start-up
		r, err := recipientFromFile(c.RecipientFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}
		if r != c.Recipient {
			return nil, fmt.Errorf("%w: the host's recipient file and MG_BACKUP_RECIPIENT differ", ErrConfig)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	unlock, err := lockDir(ctx, c.Dest)
	if err != nil {
		return nil, err
	}
	defer unlock()

	start := b.Now().UTC().Truncate(time.Second)
	m := &Manifest{Format: ManifestFormat, Target: c.Target, Label: label, StartedAt: start, Recipient: c.Recipient,
		Tools: Tools{"meshguard-backup": buildinfo.Version}}
	for k, v := range b.Tools {
		m.Tools[k] = v
	}
	m.ID = fmt.Sprintf("%s-%s-%s", c.Target, start.Format("20060102T150405Z"), label)
	removeIncomplete(c.Dest, b.Log)
	if _, err := os.Lstat(filepath.Join(c.Dest, m.ID+"."+PartManifest)); err == nil { //nolint:gosec // G703: id = target + time + validated label
		return nil, fmt.Errorf("backup set %s already exists", m.ID)
	}
	log := b.Log.With("id", m.ID, "label", label)
	log.Info("backup started")

	err = b.produce(ctx, m)
	if err == nil {
		m.FinishedAt = b.Now().UTC()
		err = writeJSONAtomic(c.Dest, m.ID+"."+PartManifest, m, 0o640)
	}
	if err != nil {
		for _, f := range m.Files { // never leave a partial set behind
			_ = os.Remove(filepath.Join(c.Dest, f.Name))
		}
		_ = os.Remove(filepath.Join(c.Dest, m.ID+"."+PartManifest)) //nolint:gosec // G703: id = target + time + validated label
		if serr := recordFailure(c, m, b.Now().UTC(), err); serr != nil {
			log.Error("status file not updated", "err", serr)
		}
		return nil, err
	}
	if err := recordSuccess(c, m); err != nil {
		log.Error("status file not updated", "err", err)
	}
	for _, name := range applyRetention(c, b.Now().UTC()) {
		log.Info("retention: removed", "file", name)
	}
	return m, nil
}

// produce writes the encrypted artifacts of the set (in m.Files as they are completed).
func (b *Backuper) produce(ctx context.Context, m *Manifest) error {
	c := b.Cfg
	if !c.IsPG() {
		m.Source = "directory " + c.Source
		return b.encryptArtifact(ctx, m, PartTar, "tar of "+c.Source+" (numeric owner, mode, mtime)",
			&funcProducer{fn: func(w io.Writer) error { return WriteTar(ctx, w, c.Source) }})
	}
	m.Source = fmt.Sprintf("postgresql://%s@%s:%s/%s", c.PG.User, c.PG.Host, c.PG.Port, c.PG.Database)
	pw, err := readPassword(c.PG.PasswordFile)
	if err != nil {
		return err
	}
	passfile := filepath.Join(c.RuntimeDir, "pgpass")
	if err := writePassfile(passfile, c.PG.User, pw); err != nil {
		return err
	}
	defer func() { _ = os.Remove(passfile) }()
	env := []string{
		"PGHOST=" + c.PG.Host, "PGPORT=" + c.PG.Port, "PGUSER=" + c.PG.User, "PGDATABASE=" + c.PG.Database,
		"PGPASSFILE=" + passfile, "PGSSLMODE=" + c.PG.SSLMode, "PGGSSENCMODE=disable", "PGCONNECT_TIMEOUT=15",
		"PGAPPNAME=meshguard-backup", "PGTZ=UTC", "LC_ALL=C", "TZ=UTC",
	}
	globals := exec.CommandContext(ctx, filepath.Join(c.PGBinDir, "pg_dumpall"), //nolint:gosec // G204: fixed tool and arguments
		"--globals-only", "--no-role-passwords", "--no-password", "--database="+c.PG.Database)
	globals.Env = env
	if err := b.encryptArtifact(ctx, m, PartGlobals, "pg_dumpall --globals-only --no-role-passwords",
		&cmdProducer{cmd: globals}); err != nil {
		return err
	}
	dump := exec.CommandContext(ctx, filepath.Join(c.PGBinDir, "pg_dump"), //nolint:gosec // G204: fixed tool and arguments
		"--format=custom", "--no-password", "--lock-wait-timeout=120s", "--dbname="+c.PG.Database)
	dump.Env = env
	return b.encryptArtifact(ctx, m, PartPGDump, "pg_dump --format=custom "+c.PG.Database, &cmdProducer{cmd: dump})
}

// writePassfile writes a libpq password file (mode 0600, on the tmpfs runtime directory) for one user.
func writePassfile(path, user, pw string) error {
	esc := strings.NewReplacer(`\`, `\\`, `:`, `\:`)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // fixed name in the runtime dir
	if err != nil {
		return fmt.Errorf("pgpass in MG_BACKUP_RUNTIME_DIR: %w", err)
	}
	_, werr := fmt.Fprintf(f, "*:*:*:%s:%s\n", esc.Replace(user), esc.Replace(pw))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// producer writes the plaintext of an artifact into the write end of the pipe to age. start takes the write end
// over (it is closed when the producer is done, so age sees the end of its input); wait reports the outcome.
type producer interface {
	start(w *os.File) error
	wait() error
}

// cmdProducer runs a tool whose standard output is the pipe itself: the plaintext goes from the child process to age
// without passing through this process.
type cmdProducer struct {
	cmd    *exec.Cmd
	stderr tailBuffer
}

func (p *cmdProducer) start(w *os.File) error {
	p.stderr.max = 4096
	p.cmd.Stdout, p.cmd.Stderr = w, &p.stderr
	err := p.cmd.Start()
	_ = w.Close() // the child holds its own copy
	return err
}

func (p *cmdProducer) wait() error {
	if err := p.cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %w: %s", filepath.Base(p.cmd.Path), err, logx.RedactString(p.stderr.lastLine()))
	}
	return nil
}

// funcProducer writes the plaintext from a goroutine of this process (the tar of the edge volume).
type funcProducer struct {
	fn   func(w io.Writer) error
	done chan error
}

func (p *funcProducer) start(w *os.File) error {
	p.done = make(chan error, 1)
	go func() {
		err := p.fn(w)
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		p.done <- err
	}()
	return nil
}

func (p *funcProducer) wait() error { return <-p.done }

// encryptArtifact streams producer → age → <dest>/.<name>.partial, hashing the ciphertext on the way, and renames
// the file into place only when the producer, age and the write all succeeded. On failure the partial file is
// removed: a truncated dump is never kept, even though age would have encrypted it.
func (b *Backuper) encryptArtifact(ctx context.Context, m *Manifest, part, content string, p producer) error {
	name := m.ID + "." + part
	final := filepath.Join(b.Cfg.Dest, name)
	partial := filepath.Join(b.Cfg.Dest, "."+name+".partial")

	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	age := exec.CommandContext(ctx, b.Cfg.AgeBin, "--encrypt", "--recipient", m.Recipient) //nolint:gosec // G204: binary from the configuration, recipient validated
	age.Env = []string{}
	age.Stdin = pr
	ageErr := &tailBuffer{max: 2048}
	age.Stderr = ageErr
	ciphertext, err := age.StdoutPipe()
	if err == nil {
		err = age.Start()
	}
	_ = pr.Close() // age holds the read end; if it dies, the producer gets EPIPE instead of blocking
	if err != nil {
		_ = pw.Close()
		return fmt.Errorf("%s: age: %w", part, err)
	}

	var f *os.File
	var n int64
	h := sha256.New()
	perr := p.start(pw) // the write end belongs to the producer from here on
	if perr == nil {
		f, err = os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o640) //nolint:gosec // name built here
		if err == nil {
			n, err = io.Copy(io.MultiWriter(f, h), ciphertext)
		}
	}
	if err != nil || perr != nil { // stop age (and with it the producer) before waiting for them
		_ = age.Process.Kill()
		_, _ = io.Copy(io.Discard, ciphertext)
	}
	if werr := age.Wait(); werr != nil {
		err = errors.Join(err, fmt.Errorf("age: %w: %s", werr, ageErr.lastLine()))
	}
	if perr == nil {
		perr = p.wait()
	}
	err = errors.Join(perr, err)
	if err == nil && n == 0 {
		err = errors.New("age produced no output")
	}
	if f != nil {
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err == nil {
		err = os.Rename(partial, final)
	}
	if err == nil {
		err = syncDir(b.Cfg.Dest)
	}
	if err != nil {
		_ = os.Remove(partial)
		return fmt.Errorf("%s: %w", part, err)
	}
	m.Files = append(m.Files, FileEntry{Name: name, Content: content, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	b.Log.Info("artifact written", "file", name, "bytes", n)
	return nil
}

// tailBuffer keeps the last max bytes written to it (stderr of a tool).
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) lastLine() string {
	lines := strings.Split(strings.TrimSpace(string(t.buf)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// lockDir takes an exclusive flock on <dir>/.lock (shared by the daemon and a `once` container mounting the same
// directory), waiting while another run holds it.
func lockDir(ctx context.Context, dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o640) //nolint:gosec // fixed name
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	fd := int(f.Fd()) //nolint:gosec // a file descriptor fits in int
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(fd, syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("lock: another backup is still running: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // destination directory from the configuration
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
