// Fixture: the worker must not import a Docker client nor the compose driver.
package main

import (
	_ "github.com/docker/docker/client"
	_ "github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
)
