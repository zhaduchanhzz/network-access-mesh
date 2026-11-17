package compose

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner runs one Docker Compose command for a project. The driver builds every argument itself (names derived from
// the slug, paths from the instance_id); nothing of a request reaches the command line.
type Runner interface {
	Compose(ctx context.Context, p Project, args ...string) error
}

// Project identifies the compose project of one instance.
type Project struct {
	Name string // mg-t-<slug>
	File string // <tenants>/<instance_id>/compose.yaml
	Dir  string // <tenants>/<instance_id> (project directory, working directory)
}

// CLI is Runner over the Docker Compose binary (standalone `docker-compose`, or the CLI plugin — same program).
type CLI struct {
	// Command is the program and its leading arguments: ["/usr/local/bin/docker-compose"] in the agent image, or
	// ["docker", "compose"].
	Command []string
	// DockerHost is passed as DOCKER_HOST (unix:///var/run/docker.sock).
	DockerHost string
	// ConfigDir is DOCKER_CONFIG and HOME of the command (a tmpfs in the agent container: rootfs is read-only).
	ConfigDir string
}

// maxOutput bounds what is kept of a failing command's output (the tail, redacted by the agent before it leaves).
const maxOutput = 4 << 10

// Compose runs `<command> --project-name <p.Name> --file <p.File> --project-directory <p.Dir> --progress quiet <args>`
// in p.Dir with a minimal environment: no COMPOSE_*, DOCKER_* or proxy variable of the agent leaks in, and no .env
// file is read (COMPOSE_DISABLE_ENV_FILE) — compose.yaml has no interpolation anyway (checkCompose).
func (c *CLI) Compose(ctx context.Context, p Project, args ...string) error {
	if len(c.Command) == 0 || !filepath.IsAbs(p.File) || !filepath.IsAbs(p.Dir) {
		return errors.New("compose: command and absolute project paths required")
	}
	argv := append([]string{}, c.Command[1:]...)
	argv = append(argv, "--project-name", p.Name, "--file", p.File, "--project-directory", p.Dir, "--progress", "quiet", "--ansi", "never")
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, c.Command[0], argv...) //nolint:gosec // G204: fixed program, arguments built by the driver from validated names
	cmd.Dir = p.Dir
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + c.ConfigDir,
		"DOCKER_CONFIG=" + c.ConfigDir,
		"DOCKER_HOST=" + c.DockerHost,
		"COMPOSE_DISABLE_ENV_FILE=1",
	}
	var out tail
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("compose %s: %w", strings.Join(args[:min(1, len(args))], " "), ctx.Err())
		}
		return fmt.Errorf("compose %s failed: %w: %s", strings.Join(args[:min(1, len(args))], " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// tail keeps the last maxOutput bytes written to it.
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > maxOutput {
		t.b = append([]byte(nil), t.b[len(t.b)-maxOutput:]...)
	}
	return len(p), nil
}

func (t *tail) String() string { return string(bytes.ToValidUTF8(t.b, []byte("?"))) }
