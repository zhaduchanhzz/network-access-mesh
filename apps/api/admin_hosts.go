package main

// `meshguard admin host-set` (P3-T04): declare the public entry, the capacity or the status of a registered host from
// the host itself — what staging needs before the first allocation (placement refuses a host without
// public_entry.ipv4). The same change as PATCH /api/v1/platform/hosts/{hostId}, through the same service
// (platform.Service.UpdateHostByName): validation mirroring the CHECKs of 0014, the 409 rules under the host row lock,
// the ETag read first (a concurrent change makes the command fail instead of overwriting it), and the audit event
// platform.host.update with the values before and after — actor_type system, actor_display "meshguard admin host-set",
// request id admin-<uuid> — in the same transaction as the change.
//
// The public IPv4 is never an argument: --public-ipv4-env names the environment variable that holds it (MG_PUBLIC_IPV4
// of the environment file, loaded with tools/mgenv.py and passed with `-e "MG_PUBLIC_IPV4=$MG_PUBLIC_IPV4"`), so it is
// never typed into a shell history or a document, and the command never prints it. Exit status: 0 done (also when
// nothing changed), 1 refused or failed (nothing written), 2 usage.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
)

const hostSetCommand = "meshguard admin host-set"

// envNameRE is the name of an environment variable the command may read.
var envNameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// hostSetRequest is what the flags ask for.
type hostSetRequest struct {
	name         string
	ipv4Env      string // "" = public_entry.ipv4 unchanged
	ipv4         string // value of ipv4Env
	mode         string // "" = unchanged
	maxInstances *int64
	status       string // "" = unchanged
}

// parseHostSet parses and checks the flags before anything is opened; the message never quotes a value read from the
// environment.
func parseHostSet(args []string, getenv func(string) string) (hostSetRequest, string) {
	fset := flag.NewFlagSet("host-set", flag.ContinueOnError)
	name := fset.String("name", "", "hosts.name of the host (e.g. mg-staging)")
	ipEnv := fset.String("public-ipv4-env", "", "NAME of the environment variable holding public_entry.ipv4")
	mode := fset.String("mode", "", "public_entry.mode: direct or vps_gateway")
	maxInst := fset.String("max-instances", "", "capacity.max_instances: 0…2147483647")
	status := fset.String("status", "", "active, draining or disabled")
	if err := parseFlags(fset, args); err != nil {
		return hostSetRequest{}, "invalid flags"
	}
	r := hostSetRequest{name: *name, ipv4Env: *ipEnv, mode: *mode, status: *status}
	switch {
	case fset.NArg() != 0:
		return r, "no positional argument expected"
	case r.name == "":
		return r, "--name is required"
	case *ipEnv == "" && *mode == "" && *maxInst == "" && *status == "":
		return r, "nothing to change: give --public-ipv4-env, --mode, --max-instances or --status"
	case r.mode != "" && r.mode != platform.EntryDirect && r.mode != platform.EntryVPSGateway:
		return r, "--mode must be direct or vps_gateway"
	case r.status != "" && !slices.Contains(platform.HostStatuses, r.status):
		return r, "--status must be active, draining or disabled"
	}
	if *maxInst != "" {
		n, err := strconv.ParseInt(*maxInst, 10, 64)
		if err != nil {
			return r, "--max-instances must be an integer"
		}
		r.maxInstances = &n
	}
	if r.ipv4Env != "" {
		if _, err := netip.ParseAddr(r.ipv4Env); err == nil || strings.ContainsAny(r.ipv4Env, ".:") {
			return r, "--public-ipv4-env takes the NAME of an environment variable (e.g. MG_PUBLIC_IPV4), never an address"
		}
		if !envNameRE.MatchString(r.ipv4Env) {
			return r, "--public-ipv4-env must name an environment variable: upper-case letters, digits and '_'"
		}
		r.ipv4 = strings.TrimSpace(getenv(r.ipv4Env))
		if r.ipv4 == "" {
			return r, r.ipv4Env + " is empty or unset in the environment of the command — load the environment file " +
				"(tools/mgenv.py) and pass it: -e \"" + r.ipv4Env + "=$" + r.ipv4Env + "\""
		}
	}
	return r, ""
}

// patch builds the change against the host as read: public_entry is replaced as a whole, so the key the flags leave
// alone keeps its current value.
func (r hostSetRequest) patch(cur platform.HostView) platform.HostPatch {
	var p platform.HostPatch
	if r.status != "" {
		p.Status = &r.status
	}
	p.MaxInstances = r.maxInstances
	if r.ipv4Env != "" || r.mode != "" {
		var e platform.PublicEntry
		if cur.PublicEntry.IsValid() {
			s := cur.PublicEntry.String()
			e.IPv4 = &s
		}
		if cur.EntryMode != "" {
			m := cur.EntryMode
			e.Mode = &m
		}
		if r.ipv4Env != "" {
			v := r.ipv4
			e.IPv4 = &v
		}
		if r.mode != "" {
			m := r.mode
			e.Mode = &m
		}
		p.PublicEntry = &e
	}
	return p
}

func runHostSet(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "host-set"
	req, msg := parseHostSet(args, aio.getenv)
	if msg != "" {
		return usageError(aio, cmd, msg)
	}
	d, err := openDeps(ctx, aio, false)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.close()
	svc := platform.New(d.st)
	cur, err := svc.GetHostByName(ctx, req.name)
	if errors.Is(err, platform.ErrNotFound) {
		return fail(aio, cmd, errors.New("no host of that name is registered (register it with POST /api/v1/platform/hosts, "+
			"or adopt-instance for the hosts of Phase 1) — nothing was written"))
	}
	if err != nil {
		return fail(aio, cmd, err)
	}
	requestID := "admin-" + uuid.Must(uuid.NewV7()).String()
	v, err := svc.UpdateHostByName(ctx, req.name, req.patch(cur), platform.HostWrite{IfMatch: cur.ETag,
		System: &platform.SystemActor{Command: hostSetCommand, RequestID: requestID}})
	if err != nil {
		return fail(aio, cmd, hostSetError(err))
	}
	printHostSet(aio.stdout, req, cur, v, requestID)
	_, _ = io.WriteString(aio.stdout, "OK\n")
	return 0
}

// hostSetError explains a refusal of the service without quoting a submitted value (the field errors name fields).
func hostSetError(err error) error {
	var (
		inv  *platform.ValidationError
		conf *platform.HostConflictError
	)
	switch {
	case errors.As(err, &inv):
		parts := make([]string, len(inv.Fields))
		for i, f := range inv.Fields {
			parts[i] = f.Field + ": " + f.Message
		}
		return errors.New("refused — " + strings.Join(parts, "; ") + " — nothing was written")
	case errors.As(err, &conf):
		return fmt.Errorf("refused — %w — nothing was written", conf)
	case errors.Is(err, platform.ErrPreconditionFailed):
		return errors.New("the host changed while the command ran — nothing was written; run it again")
	case errors.Is(err, platform.ErrNotFound):
		return errors.New("the host disappeared while the command ran — nothing was written")
	}
	return err
}

func printHostSet(w io.Writer, r hostSetRequest, before, after platform.HostView, requestID string) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	state := func(changed bool) string {
		if changed {
			return "changed"
		}
		return "unchanged"
	}
	p("host-set: host %s (%s), region %s", after.Name, after.ID, after.Region)
	if before.Status != after.Status {
		p("  status: %s → %s", before.Status, after.Status)
	} else {
		p("  status: %s (unchanged)", after.Status)
	}
	p("  capacity.max_instances: %d (%s)", after.MaxInstances, state(before.MaxInstances != after.MaxInstances))
	switch {
	case r.ipv4Env != "":
		p("  public_entry.ipv4: value of $%s (%s; the address is not printed)", r.ipv4Env,
			state(before.PublicEntry != after.PublicEntry))
	case after.PublicEntry.IsValid():
		p("  public_entry.ipv4: set (unchanged; the address is not printed)")
	default:
		p("  public_entry.ipv4: not set")
	}
	p("  public_entry.mode: %s (%s)", orText(after.EntryMode, "not set"), state(before.EntryMode != after.EntryMode))
	p("  instances not removed: %d of %d; run UIDs never used: %d; free /29: %d", after.Usage.LiveInstances,
		after.MaxInstances, after.Usage.RunUIDsFree, after.Usage.NetSlotsFree)
	switch {
	case after.Status != platform.HostActive:
		p("  placement: skips this host (status %s)", after.Status)
	case !after.PublicEntry.IsValid():
		p("  placement: skips this host (no public_entry.ipv4)")
	case int64(after.Usage.LiveInstances) >= int64(after.MaxInstances):
		p("  placement: skips this host (capacity full)")
	default:
		p("  placement: can choose this host")
	}
	p("  audit: %s (actor_type system, request %s); ETag %s", platform.ActionHostUpdate, requestID, after.ETag)
}
