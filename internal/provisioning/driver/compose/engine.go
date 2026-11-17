package compose

import (
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
	"github.com/moby/moby/api/types/container"
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
	// RemoveEdgeAttachment — P3-T03): the guard (agentspec.Guard.CheckEdgeAttach) runs before.
	ConnectNetwork(ctx context.Context, network, container string) error
	DisconnectNetwork(ctx context.Context, network, container string) error
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

func (m *mobyEngine) ConnectNetwork(ctx context.Context, nw, ctr string) error {
	_, err := m.c.NetworkConnect(ctx, nw, client.NetworkConnectOptions{Container: ctr})
	return wrap("connect network", err)
}

func (m *mobyEngine) DisconnectNetwork(ctx context.Context, nw, ctr string) error {
	_, err := m.c.NetworkDisconnect(ctx, nw, client.NetworkDisconnectOptions{Container: ctr})
	return wrap("disconnect network", err)
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
