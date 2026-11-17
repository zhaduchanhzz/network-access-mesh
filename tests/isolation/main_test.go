//go:build mgtestfixture

package isolation_test

import (
	"os"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}
