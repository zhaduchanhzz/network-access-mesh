// Fixture: the compose driver runs inside the agent and may drive Docker.
package compose

import _ "github.com/moby/moby/client"

const socket = "/var/run/docker.sock"
