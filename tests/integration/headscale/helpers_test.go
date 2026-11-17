package contract

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// Users and tags of the contract run (ID-08-valid names; the platform itself uses mg-<membership_uuid>).
const (
	userObserver = "ct-observer"
	userAlice    = "ct-alice"
	userBob      = "ct-bob"
	userOfficial = "ct-official"
	userBoot     = "ct-boot" // created by run.sh with the official image's CLI before phase 1 (P2-T10a)
)

const tagOwners = `"tagOwners":{"tag:ct-tagged":["ct-alice@"],"tag:ct-ssh":["ct-alice@"],"tag:ct-ci":["ct-alice@"]}`

// portPolicy allows exactly tcp:<port> between all nodes, so the filter a node receives identifies the policy the
// instance is ENFORCING (ports=<port>), independently of what GetPolicy reports.
func portPolicy(port int) string {
	return fmt.Sprintf(`{%s,"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:%d"]}],"ssh":[]}`, tagOwners, port)
}

// sshCheckPolicy has an SSH rule with action "check" (forbidden on tenants by lint L10; the patched build of P2-T10a
// fixes the crash of V-26, but check mode stays Post-MVP and L10 stays).
const sshCheckPolicy = `{` + tagOwners + `,"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}],` +
	`"ssh":[{"action":"check","src":["ct-alice@"],"dst":["tag:ct-ssh"],"users":["root"]}]}`

func (e *env) ensureUser(t *testing.T, inst headscale.Instance, name string) headscale.User {
	t.Helper()
	users, err := inst.ListUsers(ctx(t), headscale.UserFilter{Name: name})
	if err != nil {
		t.Fatalf("ListUsers %s: %v", name, err)
	}
	if len(users) == 1 {
		return users[0]
	}
	u, err := inst.CreateUser(ctx(t), headscale.CreateUser{Name: name, DisplayName: "contract " + name})
	if err != nil {
		t.Fatalf("CreateUser %s: %v", name, err)
	}
	return u
}

// userKey creates a single-use 10-minute key for a user (explicit expiration — V-06).
func (e *env) userKey(t *testing.T, inst headscale.Instance, userID uint64) string {
	t.Helper()
	k, err := inst.CreatePreAuthKey(ctx(t), headscale.PreAuthKeyOpts{User: userID, Expiration: time.Now().Add(10 * time.Minute)})
	if err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	return k.Key.Reveal()
}

func (e *env) tagKey(t *testing.T, inst headscale.Instance, tags ...string) string {
	t.Helper()
	k, err := inst.CreatePreAuthKey(ctx(t), headscale.PreAuthKeyOpts{Tags: tags, Expiration: time.Now().Add(10 * time.Minute)})
	if err != nil {
		t.Fatalf("CreatePreAuthKey(tags): %v", err)
	}
	return k.Key.Reveal()
}

// nodeOf finds the node registered with a fake node's current node key (ListNodes view).
func (e *env) nodeOf(t *testing.T, inst headscale.Instance, n *fakeNode) headscale.Node {
	t.Helper()
	nodes, err := inst.ListNodes(ctx(t), "")
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	want := n.Node.Public().String()
	for _, x := range nodes {
		if x.NodeKey == want {
			return x
		}
	}
	t.Fatalf("no node with the node key of %s", n.Hostname)
	return headscale.Node{}
}

// nodesOfMachine lists the nodes registered from a machine key.
func (e *env) nodesOfMachine(t *testing.T, inst headscale.Instance, n *fakeNode) []headscale.Node {
	t.Helper()
	nodes, err := inst.ListNodes(ctx(t), "")
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	want := n.Machine.Public().String()
	var out []headscale.Node
	for _, x := range nodes {
		if x.MachineKey == want {
			out = append(out, x)
		}
	}
	return out
}

func (e *env) storedPolicy(t *testing.T, inst headscale.Instance) string {
	t.Helper()
	p, err := inst.GetPolicy(ctx(t))
	if err != nil {
		if errors.Is(err, headscale.ErrNoPolicy) {
			return "<no policy>"
		}
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.Data
}

func (e *env) policyName(doc string) string {
	for port := 1000; port <= 1003; port++ {
		if doc == portPolicy(port) {
			return fmt.Sprintf("P(tcp:%d)", port)
		}
	}
	if doc == sshCheckPolicy {
		return "P(ssh-check)"
	}
	return truncate(doc, 80)
}

func expiryString(x *time.Time) string {
	if x == nil {
		return "null (never)"
	}
	return x.UTC().Format(time.RFC3339)
}

func within(a, b time.Time, tol time.Duration) bool {
	d := a.Sub(b)
	return d <= tol && d >= -tol
}

func routes(n headscale.Node) string {
	return fmt.Sprintf("approved=%v available=%v subnet=%v", n.ApprovedRoutes, n.AvailableRoutes, n.SubnetRoutes)
}

func owner(n headscale.Node) string {
	if n.User == nil {
		return "<nil>"
	}
	return n.User.Name
}

func authIDOfURL(u string) string { return u[strings.LastIndex(u, "/")+1:] }

// unknownAuthID is well-formed but never issued (built at run time — a literal would trip the secret scanner).
func unknownAuthID() string { return "hskey-" + "authreq-" + strings.Repeat("Q", 24) }
