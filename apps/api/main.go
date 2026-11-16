// Command meshguard-api serves the SaaS REST API (/api/v1) and the internal endpoints (§4.2, §13).
package main

import (
	"os"

	"github.com/zhaduchanhzz/network-access-mesh/apps/internal/runner"
)

func main() { os.Exit(runner.Main("api")) }
