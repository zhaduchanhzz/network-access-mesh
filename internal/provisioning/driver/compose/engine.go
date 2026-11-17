package compose

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Engine is the part of the Docker Engine API the driver uses. The compose driver implements it with the moby client
// (mobyEngine); unit tests use a fake. Names are exact: an object whose name merely starts like the requested one, or
// is found through an ID prefix, is "absent".
type Engine interface {
	Ping(ctx context.Context) error
	// Containers lists every container of the host, running or not, with the networks it is attached to.
	Containers(ctx context.Context) ([]Container, error)
	// Container inspects one container by exact name; nil when there is none.
	Container(ctx context.Context, name string) (*Container, error)
	// Networks lists every network of the host (no members).
	Networks(ctx context.Context) ([]Network, error)
	// Network inspects one network by exact name, with its members; nil when there is none.
	Network(ctx context.Context, name string) (*Network, error)
	CreateNetwork(ctx context.Context, spec NetworkSpec) error
	// RemoveNetwork removes a network by exact name; an absent network is not an error.
	RemoveNetwork(ctx context.Context, name string) error
	// RemoveContainer stops a container (grace period, then SIGKILL) and removes it; absent is not an error.
	RemoveContainer(ctx context.Context, name string, grace time.Duration) error
	// ConnectNetwork / DisconnectNetwork are the primitives of the edge attachment (EnsureEdgeAttachment,
	// RemoveEdgeAttachment, the edge supervisor — P3-T03): the guard (agentspec.Guard.CheckEdgeAttach) runs before a
	// connect. A disconnect of a container that is not attached is not an error.
	ConnectNetwork(ctx context.Context, network, container string) error
	DisconnectNetwork(ctx context.Context, network, container string) error
	// StopContainer stops a container (grace period, then SIGKILL); absent or already stopped is not an error.
	StopContainer(ctx context.Context, name string, grace time.Duration) error
	// EnsureImage makes an image reference (always pinned by digest — allowlist or the agent's own image) present,
	// pulling it through the daemon when it is missing (the agent itself has no network).
	EnsureImage(ctx context.Context, ref string) error
	// RunOnce runs a throw-away helper container to completion and removes it whatever happens (§11.5: configtest,
	// Noise key fingerprint). The container never has a network, a capability or a writable rootfs.
	RunOnce(ctx context.Context, s OneShot) (OneShotResult, error)
	// Exec runs a command inside a running container as the container's own user (the tenant's run_uid) — the
	// Headscale CLI over its local Unix socket (§11.3 steps 12–13). No TTY, no stdin, no environment, no privilege.
	Exec(ctx context.Context, container string, cmd []string, timeout time.Duration) (ExecResult, error)
	// ContainerStarts signals (best effort) every start of the named container — the edge supervisor reacts to a
	// recreated edge at once instead of at its next tick. The channel is closed when ctx ends or the event stream
	// fails (the caller subscribes again later; its ticker keeps running meanwhile).
	ContainerStarts(ctx context.Context, name string) <-chan struct{}
}

// Container is what the driver knows about one container.
type Container struct {
	ID, Name string
	// Image is the reference the container was created from (compose: <repository>@sha256:<digest>).
	Image  string
	Labels map[string]string
	// State: created, running, paused, restarting, removing, exited, dead.
	State string
	// Health: "" (no healthcheck), starting, healthy, unhealthy.
	Health    string
	StartedAt time.Time
	// Networks maps a network name to the DNS names of the container's endpoint (aliases ∪ Docker DNS names).
	Networks map[string][]string
	// GwPriority maps a network name to the gw_priority of the endpoint (inspect only): the edge's default gateway
	// must stay on mg-edge (§11.4 edge supervisor, §14.3).
	GwPriority map[string]int
}

// OneShot is a throw-away helper container (§11.5). Everything is set by the driver from validated values; the
// container always gets network none, a read-only rootfs, cap_drop ALL, no-new-privileges, no restart, log driver
// none (its output is read over the attach stream, never stored), and the given limits.
type OneShot struct {
	Name       string
	Image      string
	Entrypoint []string
	Cmd        []string
	User       string // uid:gid
	Labels     map[string]string
	// Binds are host paths (absolute, must exist — never created) mounted at Target.
	Binds []Bind
	// Tmpfs maps a mount point to its options (uid=…,gid=…,mode=…,size=…) — the scratch data directory of configtest.
	Tmpfs       map[string]string
	MemoryBytes int64
	NanoCPUs    int64
	PIDs        int64
	// Timeout bounds the whole run: past it the container is killed and the run fails (fail closed).
	Timeout time.Duration
	// MaxOutput bounds what is kept of stdout and of stderr (each).
	MaxOutput int
}

// Bind is one bind mount of a helper container.
type Bind struct {
	Source, Target string
	ReadOnly       bool
}

// OneShotResult is the outcome of a helper container that ran to completion.
type OneShotResult struct {
	ExitCode       int
	Stdout, Stderr []byte
	// Truncated: an output exceeded MaxOutput (the kept part is its beginning).
	Truncated bool
}

// ExecResult is the outcome of a command run inside a container.
type ExecResult struct {
	ExitCode       int
	Stdout, Stderr []byte
	Truncated      bool
}

// Network is what the driver knows about one network.
type Network struct {
	ID, Name string
	Labels   map[string]string
	Internal bool
	Subnets  []netip.Prefix
	// Members are the names of the attached containers (Network only, sorted).
	Members []string
}

// NetworkSpec is a tenant network to create.
type NetworkSpec struct {
	Name   string
	Subnet netip.Prefix
	Labels map[string]string
}

// ErrUnavailable marks a Docker Engine the agent cannot reach (retryable for the worker: gRPC UNAVAILABLE).
var ErrUnavailable = errors.New("docker engine unavailable")

// mobyEngine is Engine over the Docker Engine API (github.com/moby/moby/client, API version negotiated).
type mobyEngine struct{ c *client.Client }

// NewEngine connects to the Docker Engine at host (unix:///var/run/docker.sock). Nothing is contacted before the
// first call.
func NewEngine(host string) (Engine, error) {
	c, err := client.New(client.WithHost(host))
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &mobyEngine{c: c}, nil
}

// wrap maps an Engine API error: an unreachable daemon is UNAVAILABLE (the worker retries), the rest keeps its text.
func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	if client.IsErrConnectionFailed(err) {
		return status.Errorf(codes.Unavailable, "%s: %v", op, ErrUnavailable)
	}
	return fmt.Errorf("%s: %w", op, err)
}

func (m *mobyEngine) Ping(ctx context.Context) error {
	_, err := m.c.Ping(ctx, client.PingOptions{})
	return wrap("ping", err)
}

func (m *mobyEngine) Containers(ctx context.Context) ([]Container, error) {
	res, err := m.c.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, wrap("list containers", err)
	}
	out := make([]Container, 0, len(res.Items))
	for _, s := range res.Items {
		c := Container{ID: s.ID, Image: s.Image, Labels: s.Labels, State: string(s.State)}
		if len(s.Names) > 0 {
			c.Name = strings.TrimPrefix(s.Names[0], "/")
		}
		if s.Health != nil {
			c.Health = healthOf(string(s.Health.Status))
		}
		if s.NetworkSettings != nil {
			c.Networks = endpoints(s.NetworkSettings.Networks)
		}
		out = append(out, c)
	}
	return out, nil
}

func healthOf(s string) string {
	if s == string(container.NoHealthcheck) {
		return ""
	}
	return s
}

func endpoints(nets map[string]*network.EndpointSettings) map[string][]string {
	out := make(map[string][]string, len(nets))
	for name, ep := range nets {
		var names []string
		if ep != nil {
			names = append(append(names, ep.Aliases...), ep.DNSNames...)
		}
		sort.Strings(names)
		out[name] = names
	}
	return out
}

func (m *mobyEngine) Container(ctx context.Context, name string) (*Container, error) {
	res, err := m.c.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrap("inspect container", err)
	}
	r := res.Container
	if strings.TrimPrefix(r.Name, "/") != name {
		return nil, nil // found through an ID prefix: not the container with that name
	}
	c := &Container{ID: r.ID, Name: name}
	if r.Config != nil {
		c.Image, c.Labels = r.Config.Image, r.Config.Labels
	}
	if r.State != nil {
		c.State = string(r.State.Status)
		if r.State.Health != nil {
			c.Health = healthOf(string(r.State.Health.Status))
		}
		if t, err := time.Parse(time.RFC3339Nano, r.State.StartedAt); err == nil && t.Year() > 1 {
			c.StartedAt = t.UTC()
		}
	}
	if r.NetworkSettings != nil {
		c.Networks = endpoints(r.NetworkSettings.Networks)
		c.GwPriority = make(map[string]int, len(r.NetworkSettings.Networks))
		for name, ep := range r.NetworkSettings.Networks {
			if ep != nil {
				c.GwPriority[name] = ep.GwPriority
			}
		}
	}
	return c, nil
}

func netOf(n network.Network) Network {
	out := Network{ID: n.ID, Name: n.Name, Labels: n.Labels, Internal: n.Internal}
	for _, c := range n.IPAM.Config {
		if c.Subnet.IsValid() {
			out.Subnets = append(out.Subnets, c.Subnet)
		}
	}
	return out
}

func (m *mobyEngine) Networks(ctx context.Context) ([]Network, error) {
	res, err := m.c.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return nil, wrap("list networks", err)
	}
	out := make([]Network, 0, len(res.Items))
	for _, n := range res.Items {
		out = append(out, netOf(n.Network))
	}
	return out, nil
}

func (m *mobyEngine) Network(ctx context.Context, name string) (*Network, error) {
	res, err := m.c.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrap("inspect network", err)
	}
	if res.Network.Name != name {
		return nil, nil
	}
	n := netOf(res.Network.Network)
	for _, ep := range res.Network.Containers {
		n.Members = append(n.Members, ep.Name)
	}
	sort.Strings(n.Members)
	return &n, nil
}

func (m *mobyEngine) CreateNetwork(ctx context.Context, s NetworkSpec) error {
	ipv6 := false
	_, err := m.c.NetworkCreate(ctx, s.Name, client.NetworkCreateOptions{
		Driver:     "bridge",
		Internal:   true,
		EnableIPv6: &ipv6,
		IPAM:       &network.IPAM{Driver: "default", Config: []network.IPAMConfig{{Subnet: s.Subnet}}},
		Labels:     s.Labels,
	})
	return wrap("create network", err)
}

func (m *mobyEngine) RemoveNetwork(ctx context.Context, name string) error {
	n, err := m.Network(ctx, name)
	if err != nil || n == nil {
		return err
	}
	_, err = m.c.NetworkRemove(ctx, n.ID, client.NetworkRemoveOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return wrap("remove network", err)
}

func (m *mobyEngine) RemoveContainer(ctx context.Context, name string, grace time.Duration) error {
	c, err := m.Container(ctx, name)
	if err != nil || c == nil {
		return err
	}
	secs := int(grace / time.Second)
	if _, err := m.c.ContainerStop(ctx, c.ID, client.ContainerStopOptions{Timeout: &secs}); err != nil && !cerrdefs.IsNotFound(err) {
		return wrap("stop container", err)
	}
	_, err = m.c.ContainerRemove(ctx, c.ID, client.ContainerRemoveOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return wrap("remove container", err)
}

// attachedTo reports whether the named container has an endpoint on network nw (false when it does not exist).
func (m *mobyEngine) attachedTo(ctx context.Context, nw, ctr string) (bool, error) {
	c, err := m.Container(ctx, ctr)
	if err != nil || c == nil {
		return false, err
	}
	_, ok := c.Networks[nw]
	return ok, nil
}

// ConnectNetwork attaches with the default endpoint settings: no alias, gw_priority 0 (the edge's default gateway
// stays on mg-edge, gw_priority 1 — §14.3). Already attached is not an error.
func (m *mobyEngine) ConnectNetwork(ctx context.Context, nw, ctr string) error {
	_, err := m.c.NetworkConnect(ctx, nw, client.NetworkConnectOptions{Container: ctr})
	if err != nil {
		if ok, ierr := m.attachedTo(ctx, nw, ctr); ierr == nil && ok {
			return nil
		}
	}
	return wrap("connect network", err)
}

func (m *mobyEngine) DisconnectNetwork(ctx context.Context, nw, ctr string) error {
	_, err := m.c.NetworkDisconnect(ctx, nw, client.NetworkDisconnectOptions{Container: ctr})
	if err != nil {
		if ok, ierr := m.attachedTo(ctx, nw, ctr); ierr == nil && !ok {
			return nil
		}
	}
	return wrap("disconnect network", err)
}

func (m *mobyEngine) StopContainer(ctx context.Context, name string, grace time.Duration) error {
	c, err := m.Container(ctx, name)
	if err != nil || c == nil {
		return err
	}
	secs := int(grace / time.Second)
	if _, err := m.c.ContainerStop(ctx, c.ID, client.ContainerStopOptions{Timeout: &secs}); err != nil && !cerrdefs.IsNotFound(err) {
		return wrap("stop container", err)
	}
	return nil
}

func (m *mobyEngine) EnsureImage(ctx context.Context, ref string) error {
	if _, err := m.c.ImageInspect(ctx, ref); err == nil {
		return nil
	} else if !cerrdefs.IsNotFound(err) {
		return wrap("inspect image", err)
	}
	resp, err := m.c.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return wrap("pull image", err)
	}
	defer func() { _ = resp.Close() }()
	return wrap("pull image", resp.Wait(ctx))
}

// bounded keeps the first max bytes written to it and notes whether more came.
type bounded struct {
	b    bytes.Buffer
	max  int
	over bool
}

func (w *bounded) Write(p []byte) (int, error) {
	if room := w.max - w.b.Len(); room < len(p) {
		w.over = true
		if room > 0 {
			w.b.Write(p[:room])
		}
		return len(p), nil
	}
	w.b.Write(p)
	return len(p), nil
}

// cleanupTimeout bounds the removal of a helper container after its run (on a context of its own: the caller's may
// be over).
const cleanupTimeout = 30 * time.Second

func (m *mobyEngine) RunOnce(ctx context.Context, s OneShot) (OneShotResult, error) {
	if s.Timeout <= 0 || s.MaxOutput <= 0 || s.Name == "" || s.Image == "" {
		return OneShotResult{}, errors.New("helper container: name, image, timeout and output bound required")
	}
	mounts := make([]mount.Mount, 0, len(s.Binds))
	for _, b := range s.Binds {
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: b.Source, Target: b.Target, ReadOnly: b.ReadOnly,
			BindOptions: &mount.BindOptions{CreateMountpoint: false}})
	}
	pids := s.PIDs
	created, err := m.c.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: s.Name,
		Config: &container.Config{Image: s.Image, Entrypoint: s.Entrypoint, Cmd: s.Cmd, User: s.User, Labels: s.Labels,
			AttachStdout: true, AttachStderr: true, NetworkDisabled: true},
		HostConfig: &container.HostConfig{
			NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			LogConfig: container.LogConfig{Type: "none"}, RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
			Mounts: mounts, Tmpfs: s.Tmpfs,
			Resources: container.Resources{Memory: s.MemoryBytes, MemorySwap: s.MemoryBytes, NanoCPUs: s.NanoCPUs, PidsLimit: &pids},
		},
	})
	if err != nil {
		return OneShotResult{}, wrap("create helper container", err)
	}
	defer func() { // whatever happened: the helper never outlives its run
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		_, _ = m.c.ContainerRemove(rctx, created.ID, client.ContainerRemoveOptions{Force: true})
	}()
	rctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	att, err := m.c.ContainerAttach(rctx, created.ID, client.ContainerAttachOptions{Stream: true, Stdout: true, Stderr: true})
	if err != nil {
		return OneShotResult{}, wrap("attach helper container", err)
	}
	defer att.Close()
	// registered before the start: a fast exit is not missed
	wait := m.c.ContainerWait(rctx, created.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	stdout, stderr := &bounded{max: s.MaxOutput}, &bounded{max: s.MaxOutput}
	copied := make(chan error, 1)
	go func() { _, err := stdcopy.StdCopy(stdout, stderr, att.Reader); copied <- err }()
	if _, err := m.c.ContainerStart(rctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return OneShotResult{}, wrap("start helper container", err)
	}
	var code int64
	select {
	case r := <-wait.Result:
		code = r.StatusCode
	case err := <-wait.Error:
		if rctx.Err() != nil {
			return OneShotResult{}, status.Errorf(codes.DeadlineExceeded, "helper container %s did not finish within %s (killed)", s.Name, s.Timeout)
		}
		return OneShotResult{}, wrap("wait helper container", err)
	}
	select { // the output stream ends with the process; bounded by the run's deadline
	case err := <-copied:
		if err != nil {
			return OneShotResult{}, wrap("helper container output", err)
		}
	case <-rctx.Done():
		return OneShotResult{}, status.Errorf(codes.DeadlineExceeded, "helper container %s: output not complete within %s", s.Name, s.Timeout)
	}
	return OneShotResult{ExitCode: int(code), Stdout: stdout.b.Bytes(), Stderr: stderr.b.Bytes(), Truncated: stdout.over || stderr.over}, nil
}

func (m *mobyEngine) Exec(ctx context.Context, ctr string, cmd []string, timeout time.Duration) (ExecResult, error) {
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ec, err := m.c.ExecCreate(ectx, ctr, client.ExecCreateOptions{AttachStdout: true, AttachStderr: true, Cmd: cmd})
	if err != nil {
		return ExecResult{}, wrap("exec create", err)
	}
	att, err := m.c.ExecAttach(ectx, ec.ID, client.ExecAttachOptions{})
	if err != nil {
		return ExecResult{}, wrap("exec attach", err)
	}
	defer att.Close()
	stop := context.AfterFunc(ectx, func() { _ = att.Conn.Close() }) // a hung command cannot block the agent
	defer stop()
	stdout, stderr := &bounded{max: maxExecOutput}, &bounded{max: maxExecOutput}
	if _, err := stdcopy.StdCopy(stdout, stderr, att.Reader); err != nil && ectx.Err() == nil {
		return ExecResult{}, wrap("exec output", err)
	}
	if ectx.Err() != nil {
		return ExecResult{}, status.Errorf(codes.DeadlineExceeded, "command in %s did not finish within %s", ctr, timeout)
	}
	// the stream ended with the process; its exit code may be recorded a moment later
	for range 50 {
		in, err := m.c.ExecInspect(ectx, ec.ID, client.ExecInspectOptions{})
		if err != nil {
			return ExecResult{}, wrap("exec inspect", err)
		}
		if !in.Running {
			return ExecResult{ExitCode: in.ExitCode, Stdout: stdout.b.Bytes(), Stderr: stderr.b.Bytes(), Truncated: stdout.over || stderr.over}, nil
		}
		select {
		case <-ectx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
	return ExecResult{}, status.Errorf(codes.DeadlineExceeded, "command in %s: no exit code", ctr)
}

// maxExecOutput bounds what is kept of the output of a CLI command (a policy is at most 256 KiB — agentspec).
const maxExecOutput = 1 << 20

func (m *mobyEngine) ContainerStarts(ctx context.Context, name string) <-chan struct{} {
	out := make(chan struct{}, 1)
	f := make(client.Filters).Add("type", "container").Add("event", "start").Add("container", name)
	res := m.c.Events(ctx, client.EventsListOptions{Filters: f})
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-res.Err:
				_ = err // the stream ended (an error or ctx): the caller subscribes again later
				return
			case msg, ok := <-res.Messages:
				if !ok {
					return
				}
				if strings.TrimPrefix(msg.Actor.Attributes["name"], "/") != name {
					continue // the "container" filter also matches an ID prefix
				}
				select {
				case out <- struct{}{}:
				default: // a trigger is already pending
				}
			}
		}
	}()
	return out
}

// inventory is agentspec.Inventory over an Engine: what the guard checks before anything is touched. Every network
// and container of the host is listed (an unlabelled object with a derived name must be refused, not missed);
// members and their DNS names come from the containers' endpoints.
type inventory struct{ e Engine }

// NewInventory returns the guard's view of Docker.
func NewInventory(e Engine) agentspec.Inventory { return inventory{e} }

func (i inventory) Networks(ctx context.Context) ([]agentspec.NetworkInfo, error) {
	nets, err := i.e.Networks(ctx)
	if err != nil {
		return nil, err
	}
	ctrs, err := i.e.Containers(ctx)
	if err != nil {
		return nil, err
	}
	members := map[string][]agentspec.Member{}
	for _, c := range ctrs {
		// the container list of the Engine API carries the endpoints but not their aliases/DNS names (Docker 29):
		// inspect every container attached to a user-defined network (the alias check of P3-T03 needs them)
		if slices.ContainsFunc(slices.Collect(maps.Keys(c.Networks)), func(nw string) bool { return nw != "none" && nw != "host" && nw != "bridge" }) {
			full, err := i.e.Container(ctx, c.Name)
			if err != nil {
				return nil, err
			}
			if full != nil {
				c.Networks = full.Networks
			}
		}
		for nw, names := range c.Networks {
			members[nw] = append(members[nw], agentspec.Member{Container: c.Name, Aliases: names})
		}
	}
	out := make([]agentspec.NetworkInfo, 0, len(nets))
	for _, n := range nets {
		ms := members[n.Name]
		sort.Slice(ms, func(a, b int) bool { return ms[a].Container < ms[b].Container })
		out = append(out, agentspec.NetworkInfo{Name: n.Name, Labels: n.Labels, Subnets: n.Subnets, Internal: n.Internal, Members: ms})
	}
	return out, nil
}

func (i inventory) Containers(ctx context.Context) ([]agentspec.ContainerInfo, error) {
	ctrs, err := i.e.Containers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]agentspec.ContainerInfo, 0, len(ctrs))
	for _, c := range ctrs {
		out = append(out, agentspec.ContainerInfo{Name: c.Name, Labels: c.Labels})
	}
	return out, nil
}
