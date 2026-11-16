// Command derpprobe checks who the DERP relay of one tenant accepts (IT-09, P1-T12b; §10.1 of the master plan).
//
// It connects to <url> (e.g. https://tenant-a.<mesh_domain>/derp, through the edge) with the official DERP client of
// Tailscale (tailscale.com/derp/derphttp, pinned in go.mod) and a node private key, then waits for the server's
// first frame. Headscale's embedded DERP runs with verify_clients: a key that is not a registered node of THIS tenant
// must be rejected (the server closes the connection instead of sending ServerInfo).
//
//	derpprobe -url URL -random                 # fresh random node key  → must be rejected
//	derpprobe -url URL -key-file F             # F holds "privkey:<hex>" (read from a lab client's state)
//
// Exit codes: 0 = accepted, 1 = rejected, 2 = usage or setup error. Only the public part of the key is printed.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

func main() {
	os.Exit(run())
}

func run() int {
	url := flag.String("url", "", "DERP URL, e.g. https://tenant-a.example.com/derp")
	random := flag.Bool("random", false, "use a fresh random node key")
	keyFile := flag.String("key-file", "", `file holding a node private key ("privkey:<hex>")`)
	timeout := flag.Duration("timeout", 10*time.Second, "time to wait for the first frame")
	flag.Parse()
	if *url == "" || *random == (*keyFile != "") {
		fmt.Fprintln(os.Stderr, "usage: derpprobe -url URL (-random | -key-file F)")
		return 2
	}

	var priv key.NodePrivate
	if *random {
		priv = key.NewNode()
	} else {
		raw, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read key:", err)
			return 2
		}
		if err := priv.UnmarshalText([]byte(strings.TrimSpace(string(raw)))); err != nil {
			fmt.Fprintln(os.Stderr, "parse key: not a node private key")
			return 2
		}
	}
	pub := priv.Public().ShortString()

	quiet := func(string, ...any) {}
	c, err := derphttp.NewClient(priv, *url, quiet, netmon.NewStatic())
	if err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		return 2
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		fmt.Printf("rejected key=%s: connect: %v\n", pub, err)
		return 1
	}
	type result struct {
		msg derp.ReceivedMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, err := c.Recv()
		ch <- result{m, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			fmt.Printf("rejected key=%s: %v\n", pub, r.err)
			return 1
		}
		if _, ok := r.msg.(derp.ServerInfoMessage); ok {
			fmt.Printf("accepted key=%s: ServerInfo received\n", pub)
		} else {
			fmt.Printf("accepted key=%s: first frame %T\n", pub, r.msg)
		}
		return 0
	case <-ctx.Done():
		fmt.Printf("rejected key=%s: no frame within %s\n", pub, *timeout)
		return 1
	}
}
