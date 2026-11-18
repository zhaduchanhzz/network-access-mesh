package runner

import (
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
)

// TestNewInstanceOps — the wiring of P3-T13a: without MG_AGENT_* the worker runs neither instance.restart nor
// instance.upgrade (a warning; the jobs stay queued) and builds nothing else for them.
func TestNewInstanceOps(t *testing.T) {
	var logs syncBuffer
	d := &deps{log: newTestLogger(&logs)}
	defer d.close()
	rs, up, err := newInstanceOps(config.Config{}, d, nil, nil)
	if rs != nil || up != nil || err != nil ||
		!strings.Contains(logs.String(), "instance.restart and instance.upgrade are not run by this worker") {
		t.Fatalf("without agent: %v %v %v\n%s", rs, up, err, logs.String())
	}
}
