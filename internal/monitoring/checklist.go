package monitoring

import (
	"net/netip"
	"slices"
	"strconv"
)

// The checklist of a connectivity diagnosis (§9.5): commands the user runs on the devices, since the server cannot
// observe the path. Each command has a stable ID (the Portal explains it and what to expect in the user's language),
// the operating system, the device it runs on and the exact text with the target's address filled in. The commands
// are the official client's CLI (1.104.x — the same on Linux, macOS and Windows; on macOS the CLI of the App Store
// build is /Applications/Tailscale.app/Contents/MacOS/Tailscale) and a real TCP connection — never `tailscale ping`
// alone to judge the policy: it uses disco packets the policy does not filter (HS-25, CL-09). Mobile clients have no
// CLI: the Portal points them to the app's own status screen.

// Operating systems of the checklist.
const (
	OSLinux   = "linux"
	OSMacOS   = "macos"
	OSWindows = "windows"
)

// ChecklistOS lists the operating systems of a checklist, in order.
var ChecklistOS = []string{OSLinux, OSMacOS, OSWindows}

// Where a command runs.
const (
	RunOnSource = "source"
	RunOnTarget = "target"
)

// Command IDs (and what the output should show — the Portal's text per ID).
const (
	CmdStatus       = "status"        // the target (or its router) is listed; its column: direct <ip:port>, relay "<code>", or "-"/idle
	CmdPing         = "ping"          // pong … via <ip>:<port> (direct) or via DERP(<code>) (relay) — reachability, not policy
	CmdNetcheck     = "netcheck"      // UDP: true; the nearest DERP is the tenant's region
	CmdDebugDERP    = "debug_derp"    // Info has the DERP connection and the STUN reply; Errors empty (IPv6 errors aside)
	CmdAcceptRoutes = "accept_routes" // Linux does not accept subnet routes by default
	CmdTCP          = "tcp_connect"   // a real TCP connection to the port — what the policy decides
	CmdHTTP         = "http_probe"    // an HTTP answer on a web port
	CmdListen       = "listen_check"  // on the target: something listens on the port
)

// PlaceholderHost stands for an address the user picks inside a subnet resource.
const PlaceholderHost = "<host>"

// Command is one step of the checklist.
type Command struct {
	ID      string
	OS      string
	RunOn   string
	Command string
}

var webPorts = map[int]string{80: "http", 8080: "http", 8000: "http", 443: "https", 8443: "https"}

// targetAddress is the address the commands use: the target device's first IPv4 (else its first address), a resource
// address when it is a single host, else PlaceholderHost. via is the tailnet address `tailscale ping` aims at (the
// target device, or the first router of a resource) — "" when there is none.
func targetAddress(t Target) (host, via string) {
	switch {
	case t.Device != nil:
		a := firstAddr(t.Device.Addresses)
		if a == "" { // no address in the register: the MagicDNS name, else a placeholder
			if a = t.Device.GivenName; a == "" {
				a = PlaceholderHost
			}
		}
		return a, a
	case t.Resource != nil:
		host = PlaceholderHost
		if t.Resource.Address.IsSingleIP() {
			host = t.Resource.Address.Addr().String()
		}
		if inTailnet(t.Resource.Address) {
			return host, host
		}
		for _, r := range t.Routers {
			if a := firstAddr(r.Addresses); a != "" {
				return host, a
			}
		}
		return host, ""
	}
	return PlaceholderHost, ""
}

func firstAddr(as []netip.Addr) string {
	for _, a := range as {
		if a.Is4() {
			return a.String()
		}
	}
	if len(as) > 0 {
		return as[0].String()
	}
	return ""
}

// Checklist builds the commands of a diagnosis (deterministic: same inputs, same list).
func Checklist(t Target, port int, relayCode string) []Command {
	host, via := targetAddress(t)
	subnet := t.Resource != nil && !inTailnet(t.Resource.Address)
	out := []Command{}
	for _, os := range ChecklistOS {
		add := func(id, runOn, cmd string) { out = append(out, Command{ID: id, OS: os, RunOn: runOn, Command: cmd}) }
		const cli = "tailscale"
		add(CmdStatus, RunOnSource, cli+" status")
		if via != "" {
			add(CmdPing, RunOnSource, cli+" ping --c 5 "+via)
		}
		add(CmdNetcheck, RunOnSource, cli+" netcheck")
		if relayCode != "" {
			add(CmdDebugDERP, RunOnSource, cli+" debug derp "+relayCode)
		}
		if subnet && os == OSLinux {
			add(CmdAcceptRoutes, RunOnSource, "sudo tailscale set --accept-routes")
		}
		if port > 0 {
			p := strconv.Itoa(port)
			switch os {
			case OSWindows:
				add(CmdTCP, RunOnSource, "Test-NetConnection -ComputerName "+host+" -Port "+p)
			default:
				add(CmdTCP, RunOnSource, "nc -vz -w 5 "+host+" "+p)
			}
			if scheme, ok := webPorts[port]; ok {
				curl, null := "curl", "/dev/null"
				if os == OSWindows {
					curl, null = "curl.exe", "NUL"
				}
				add(CmdHTTP, RunOnSource, curl+" -sS -o "+null+" -w \"%{http_code}\\n\" --connect-timeout 5 "+
					scheme+"://"+hostForURL(host)+":"+p+"/")
			}
			if t.Device != nil {
				switch os {
				case OSWindows:
					add(CmdListen, RunOnTarget, "Get-NetTCPConnection -State Listen -LocalPort "+p)
				case OSMacOS:
					add(CmdListen, RunOnTarget, "lsof -nP -iTCP:"+p+" -sTCP:LISTEN")
				default:
					add(CmdListen, RunOnTarget, "ss -ltn 'sport = :"+p+"'")
				}
			}
		}
	}
	return out
}

func hostForURL(h string) string {
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
		return "[" + h + "]"
	}
	return h
}

// commandIDs lists the distinct command IDs of a checklist, in first-seen order (tests, the Portal).
func commandIDs(cs []Command) []string {
	var out []string
	for _, c := range cs {
		if !slices.Contains(out, c.ID) {
			out = append(out, c.ID)
		}
	}
	return out
}
