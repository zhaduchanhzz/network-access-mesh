// Fixture of TestDockerCheckCatchesViolations: the agent may drive Docker (never compiled — testdata).
package main

import (
	_ "github.com/docker/docker/client"
	_ "github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
)

const socket = "/var/run/docker.sock"
