//go:build linux

package compose

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// fakeEngine is an in-memory Docker Engine: containers and networks by name; members derived from the containers'
// endpoints, like the real engine.
type fakeEngine struct {
	mu    sync.Mutex
	ctrs  map[string]*Container
	nets  map[string]*Network
	seq   int
	calls []string
	// createHook makes the next CreateNetwork fail after running it (a concurrent creation).
	createHook func(*fakeEngine)
	// hs is the Headscale of each tenant container (by container name): its instance directory, policy and API keys.
	hs map[string]*fakeHS
	// runs records every helper container (RunOnce).
	runs []OneShot
	// configtest decides the outcome of `headscale configtest` from the config.yaml it is given (nil: valid).
	configtest func(cfg []byte) OneShotResult
	// runErr / execErr make RunOnce / Exec fail (Docker unavailable, timeout); createOutput replaces the output of
	// `apikeys create`.
	runErr, execErr error
	createOutput    []byte
	starts          chan struct{}
	// imageVersion is the version label of every image; offline records the policies set by the offline policy helper.
	imageVersion string
	offline      [][]byte
}

// fakeHS is the state of the Headscale CLI of one instance.
type fakeHS struct {
	dir    string // instance directory
	policy []byte // nil: no policy (allow-all window)
	keys   []fakeKey
	sets   int // `policy set` calls
}

type fakeKey struct {
	id                  uint64
	prefix, secret      string
	expiration, created time.Time
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{ctrs: map[string]*Container{}, nets: map[string]*Network{}, hs: map[string]*fakeHS{}, starts: make(chan struct{}, 1)}
}

func (f *fakeEngine) id() string {
	f.seq++
	return fmt.Sprintf("%064x", f.seq)
}

func (f *fakeEngine) record(s string) { f.calls = append(f.calls, s) }

func (f *fakeEngine) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if len(c) >= len(prefix) && c[:len(prefix)] == prefix {
			n++
		}
	}
	return n
}

func copyCtr(c *Container) Container {
	out := *c
	out.Labels = map[string]string{}
	for k, v := range c.Labels {
		out.Labels[k] = v
	}
	out.Networks = map[string][]string{}
	for k, v := range c.Networks {
		out.Networks[k] = slices.Clone(v)
	}
	if c.GwPriority != nil {
		out.GwPriority = map[string]int{}
		for k, v := range c.GwPriority {
			out.GwPriority[k] = v
		}
	}
	return out
}

func (f *fakeEngine) Ping(context.Context) error { return nil }

func (f *fakeEngine) Containers(context.Context) ([]Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Container{}
	for _, c := range f.ctrs {
		out = append(out, copyCtr(c))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func (f *fakeEngine) Container(_ context.Context, name string) (*Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.ctrs[name]
	if !ok {
		return nil, nil
	}
	out := copyCtr(c)
	return &out, nil
}

func (f *fakeEngine) Networks(context.Context) ([]Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Network{}
	for _, n := range f.nets {
		cp := *n
		cp.Members = nil
		out = append(out, cp)
	}
	return out, nil
}

func (f *fakeEngine) Network(_ context.Context, name string) (*Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nets[name]
	if !ok {
		return nil, nil
	}
	cp := *n
	cp.Members = nil
	for _, c := range f.ctrs {
		if _, on := c.Networks[name]; on {
			cp.Members = append(cp.Members, c.Name)
		}
	}
	sort.Strings(cp.Members)
	return &cp, nil
}

func (f *fakeEngine) CreateNetwork(_ context.Context, s NetworkSpec) error {
	f.mu.Lock()
	hook := f.createHook
	f.createHook = nil
	f.record("CreateNetwork " + s.Name)
	f.mu.Unlock()
	if hook != nil {
		hook(f)
		return errors.New("network with name " + s.Name + " already exists")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.nets[s.Name]; ok {
		return errors.New("network with name " + s.Name + " already exists")
	}
	f.nets[s.Name] = &Network{ID: f.id(), Name: s.Name, Labels: s.Labels, Internal: true, Subnets: []netip.Prefix{s.Subnet}}
	return nil
}

func (f *fakeEngine) addNetwork(n Network) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n.ID = f.id()
	f.nets[n.Name] = &n
}

func (f *fakeEngine) addContainer(c Container) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c.ID = f.id()
	f.ctrs[c.Name] = &c
}

func (f *fakeEngine) RemoveNetwork(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("RemoveNetwork " + name)
	for _, c := range f.ctrs {
		if _, on := c.Networks[name]; on {
			return errors.New("network " + name + " has active endpoints")
		}
	}
	delete(f.nets, name)
	return nil
}

func (f *fakeEngine) RemoveContainer(_ context.Context, name string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("RemoveContainer " + name)
	delete(f.ctrs, name)
	return nil
}

func (f *fakeEngine) ConnectNetwork(_ context.Context, nw, ctr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.ctrs[ctr]
	if !ok || f.nets[nw] == nil {
		return errors.New("no such container or network")
	}
	c.Networks[nw] = []string{ctr}
	return nil
}

func (f *fakeEngine) DisconnectNetwork(_ context.Context, nw, ctr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DisconnectNetwork " + nw + " " + ctr)
	if c, ok := f.ctrs[ctr]; ok {
		delete(c.Networks, nw)
	}
	return nil
}

func (f *fakeEngine) StopContainer(_ context.Context, name string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("StopContainer " + name)
	if c, ok := f.ctrs[name]; ok {
		c.State, c.Health = "exited", ""
	}
	return nil
}

func (f *fakeEngine) ImageVersion(context.Context, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.imageVersion, nil
}

func (f *fakeEngine) EnsureImage(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EnsureImage " + ref)
	return nil
}

func (f *fakeEngine) ContainerStarts(ctx context.Context, _ string) <-chan struct{} {
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-f.starts:
				select {
				case out <- struct{}{}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

func (f *fakeEngine) helperRuns(cmd string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.runs {
		if len(r.Cmd) > 0 && r.Cmd[0] == cmd {
			n++
		}
	}
	return n
}

func (f *fakeEngine) setRunErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runErr = err
}

// RunOnce plays the two helper containers of the driver: the fingerprint helper runs the agent's own code on the bind
// mount (as the real helper does inside the agent image), configtest reads the config.yaml it is given.
func (f *fakeEngine) RunOnce(_ context.Context, s OneShot) (OneShotResult, error) {
	f.mu.Lock()
	f.runs = append(f.runs, s)
	err, hook := f.runErr, f.configtest
	f.mu.Unlock()
	if err != nil {
		return OneShotResult{}, err
	}
	src := map[string]string{}
	for _, b := range s.Binds {
		if _, err := os.Stat(b.Source); err != nil { // create_host_path: false
			return OneShotResult{}, fmt.Errorf("invalid mount config: bind source path does not exist: %s", b.Source)
		}
		src[b.Target] = b.Source
	}
	switch {
	case slices.Equal(s.Cmd, []string{FingerprintCommand}):
		fp, err := FingerprintNoiseKeyFile(filepath.Join(src["/var/lib/headscale"], "noise_private.key"))
		switch {
		case errors.Is(err, ErrNoiseKeyAbsent):
			return OneShotResult{ExitCode: FingerprintExitAbsent}, nil
		case errors.Is(err, ErrNoiseKeyInvalid):
			return OneShotResult{ExitCode: FingerprintExitInvalid}, nil
		case err != nil:
			return OneShotResult{ExitCode: 1}, nil
		}
		return OneShotResult{Stdout: []byte(fp + "\n")}, nil
	case len(s.Entrypoint) == 1 && s.Entrypoint[0] == HelperBinary && len(s.Cmd) == 1 && s.Cmd[0] != FingerprintCommand:
		return f.backupHelper(s, src)
	case len(s.Cmd) > 1 && s.Cmd[0] == "policy":
		return f.offlinePolicy(s, src)
	case slices.Equal(s.Cmd, []string{"configtest"}):
		cfg, err := os.ReadFile(filepath.Join(src["/etc/headscale"], "config.yaml"))
		if err != nil {
			return OneShotResult{ExitCode: 1, Stderr: []byte("error loading config")}, nil
		}
		if hook != nil {
			return hook(cfg), nil
		}
		return OneShotResult{Stdout: []byte(`{"level":"info","message":"Opening database"}` + "\n")}, nil
	}
	return OneShotResult{}, fmt.Errorf("fake: unknown helper %v", s.Cmd)
}

// Exec plays the Headscale CLI of a running tenant container.
func (f *fakeEngine) Exec(_ context.Context, ctr string, cmd []string, _ time.Duration) (ExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Exec " + strings.Join(cmd, " "))
	if f.execErr != nil {
		return ExecResult{}, f.execErr
	}
	c, ok := f.ctrs[ctr]
	if !ok || c.State != "running" {
		return ExecResult{}, fmt.Errorf("container %s is not running", ctr)
	}
	hs := f.hs[ctr]
	if hs == nil || len(cmd) < 3 || cmd[0] != "headscale" {
		return ExecResult{ExitCode: 127}, nil
	}
	ok0 := func(out string) (ExecResult, error) { return ExecResult{Stdout: []byte(out)}, nil }
	switch strings.Join(cmd[1:3], " ") {
	case "policy get":
		if hs.policy == nil {
			return ExecResult{ExitCode: 1, Stderr: []byte(`{"error": "loading ACL policy: acl policy not found"}`)}, nil
		}
		return ok0(string(hs.policy) + "\n")
	case "policy set":
		raw, err := os.ReadFile(filepath.Join(hs.dir, "config", strings.TrimPrefix(cmd[4], "/etc/headscale/")))
		if err != nil {
			return ExecResult{ExitCode: 1, Stderr: []byte("Error: reading the policy file")}, nil
		}
		hs.policy, hs.sets = raw, hs.sets+1
		return ok0("Policy updated.\n")
	case "apikeys list":
		if len(hs.keys) == 0 {
			return ok0("null\n")
		}
		type ts struct {
			Seconds int64 `json:"seconds"`
			Nanos   int32 `json:"nanos"`
		}
		var out []map[string]any
		for _, k := range hs.keys {
			out = append(out, map[string]any{"id": k.id, "prefix": "hskey-api-" + k.prefix + "-***",
				"expiration": ts{k.expiration.Unix(), int32(k.expiration.Nanosecond())}, "created_at": ts{k.created.Unix(), 0}}) //nolint:gosec // test
		}
		raw, _ := json.MarshalIndent(out, "", "\t")
		return ok0(string(raw) + "\n")
	case "apikeys create":
		hours, err := strconv.Atoi(strings.TrimSuffix(cmd[4], "h"))
		if err != nil || !strings.HasSuffix(cmd[4], "h") {
			return ExecResult{ExitCode: 1, Stderr: []byte("Error: invalid expiration")}, nil
		}
		k := fakeKey{id: uint64(len(hs.keys) + 1), prefix: randomURLSafe(12), secret: randomURLSafe(64), created: time.Now(), //nolint:gosec // G115: test
			expiration: time.Now().Add(time.Duration(hours) * time.Hour)}
		hs.keys = append(hs.keys, k)
		if f.createOutput != nil {
			return ExecResult{Stdout: append([]byte(nil), f.createOutput...)}, nil
		}
		return ok0(`"hskey-api-` + k.prefix + "-" + k.secret + "\"\n")
	case "apikeys expire":
		id, _ := strconv.ParseUint(cmd[4], 10, 64)
		for i := range hs.keys {
			if hs.keys[i].id == id {
				hs.keys[i].expiration = time.Now()
				return ok0("Key expired\n")
			}
		}
		return ExecResult{ExitCode: 1, Stderr: []byte("Error: key not found")}, nil
	}
	return ExecResult{ExitCode: 1, Stderr: []byte("Error: unknown command")}, nil
}

func randomURLSafe(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// newNoiseKey is a noise_private.key as Headscale writes it ("privkey:" + 64 hex, no newline).
func newNoiseKey() []byte {
	var k [32]byte
	_, _ = rand.Read(k[:])
	return []byte("privkey:" + hex.EncodeToString(k[:]))
}

// headscaleStarts plays what Headscale does at a start in data/ (owned by run_uid): it creates its keys and database
// when they are missing (RT-06 — exactly what the start guard must prevent for an activated instance). A missing
// data/ fails the start, as create_host_path: false does.
func headscaleStarts(dir, user string) error {
	data := filepath.Join(dir, "data")
	if _, err := os.Stat(data); err != nil {
		return fmt.Errorf("invalid mount config: bind source path does not exist: %s", data)
	}
	uid, _ := strconv.Atoi(strings.Split(user, ":")[0])
	for _, f := range []struct {
		name    string
		content []byte
	}{{"noise_private.key", newNoiseKey()}, {"derp_server_private.key", newNoiseKey()}, {"db.sqlite", validDB()}} {
		p := filepath.Join(data, f.name)
		if _, err := os.Lstat(p); err == nil {
			continue
		}
		if err := os.WriteFile(p, f.content, 0o600); err != nil {
			return err
		}
		if err := os.Lchown(p, uid, uid); err != nil {
			return err
		}
	}
	return nil
}

// fakeCompose plays docker compose against fakeEngine from the compose.yaml on disk.
type fakeCompose struct {
	e     *fakeEngine
	mu    sync.Mutex
	calls []string
	fail  error
}

func (r *fakeCompose) count(cmd string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c == cmd {
			n++
		}
	}
	return n
}

type composeFile struct {
	Name     string `yaml:"name"`
	Services map[string]struct {
		Image         string            `yaml:"image"`
		User          string            `yaml:"user"`
		ContainerName string            `yaml:"container_name"`
		Labels        map[string]string `yaml:"labels"`
		Networks      map[string]struct {
			Aliases []string `yaml:"aliases"`
		} `yaml:"networks"`
	} `yaml:"services"`
}

func (r *fakeCompose) Compose(_ context.Context, p Project, args ...string) error {
	r.mu.Lock()
	r.calls = append(r.calls, args[0])
	fail := r.fail
	r.mu.Unlock()
	if fail != nil {
		return fail
	}
	f := r.e
	if args[0] == "down" {
		f.mu.Lock()
		defer f.mu.Unlock()
		for name, c := range f.ctrs {
			if c.Labels[agentspec.LabelComposeProject] == p.Name {
				delete(f.ctrs, name)
			}
		}
		return nil
	}
	raw, err := os.ReadFile(p.File)
	if err != nil {
		return fmt.Errorf("compose: %w", err)
	}
	var cf composeFile
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		return err
	}
	if cf.Name != p.Name {
		return errors.New("compose: project name differs from the file")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, svc := range cf.Services {
		c := f.ctrs[svc.ContainerName]
		switch args[0] {
		case "up":
			for nw := range svc.Networks {
				if f.nets[nw] == nil {
					return fmt.Errorf("network %s declared as external, but could not be found", nw)
				}
			}
			labels := map[string]string{agentspec.LabelComposeProject: p.Name}
			for k, v := range svc.Labels {
				labels[k] = v
			}
			if c == nil || c.Image != svc.Image || !mapsEqual(c.Labels, labels) {
				c = &Container{ID: f.id(), Name: svc.ContainerName, Image: svc.Image, Labels: labels, Networks: map[string][]string{}}
				for nw, ep := range svc.Networks {
					c.Networks[nw] = append([]string{svc.ContainerName}, ep.Aliases...)
				}
				f.ctrs[c.Name] = c
			}
			if c.State != "running" {
				if err := headscaleStarts(p.Dir, svc.User); err != nil {
					return err
				}
				c.State, c.Health, c.StartedAt = "running", "healthy", time.Now().UTC()
			}
			if f.hs[c.Name] == nil {
				f.hs[c.Name] = &fakeHS{dir: p.Dir}
			}
		case "stop":
			if c != nil {
				c.State, c.Health = "exited", ""
			}
		case "start", "restart":
			if c != nil {
				if err := headscaleStarts(p.Dir, svc.User); err != nil {
					return err
				}
				c.State, c.Health, c.StartedAt = "running", "healthy", time.Now().UTC()
			}
		}
	}
	return nil
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
