// Command meshguard-worker runs background jobs: orchestrator, inventory sync, key rotation, backups (§4.2, §13.5).
package main

import (
	"os"

	"github.com/zhaduchanhzz/network-access-mesh/apps/internal/runner"
)

func main() { os.Exit(runner.Main("worker")) }
