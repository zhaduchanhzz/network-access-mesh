//go:build linux

package compose

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
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
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{ctrs: map[string]*Container{}, nets: map[string]*Network{}}
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
	if c, ok := f.ctrs[ctr]; ok {
		delete(c.Networks, nw)
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
				c.State, c.Health, c.StartedAt = "running", "healthy", time.Now().UTC()
			}
		case "stop":
			if c != nil {
				c.State, c.Health = "exited", ""
			}
		case "start", "restart":
			if c != nil {
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
