package agentspec

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

// aliasPrefix is the prefix of the name the edge routes a tenant to (hs-<slug>, §14.6).
const aliasPrefix = "hs-"

// maxEdgeAliases bounds the list (one per tenant network in normal operation).
const maxEdgeAliases = 4 * maxInstances

// EdgeAliases lists every hs-* name on the networks the edge is attached to: for each such network, each member whose
// container name or network-scoped alias (Docker DNS name) starts with hs-. It reads the inventory only — the input of
// reconcile's alias check (P3-T12, §11.4: hs-<slug> must exist once, on the tenant's own network), the same view as
// CheckEdgeAttach. Without Docker access (Inventory nil) the list is empty.
func (g *Guard) EdgeAliases(ctx context.Context) ([]*agentv1.EdgeAlias, error) {
	if g.Inventory == nil {
		return nil, nil
	}
	nets, err := g.Inventory.Networks(ctx)
	if err != nil {
		return nil, fmt.Errorf("inventory of networks: %w", err)
	}
	type key struct{ network, container, alias string }
	seen := map[key]bool{}
	var out []*agentv1.EdgeAlias
	for _, nw := range nets {
		if !slices.ContainsFunc(nw.Members, func(m Member) bool { return m.Container == g.Edge }) {
			continue
		}
		for _, m := range nw.Members {
			for _, name := range append([]string{m.Container}, m.Aliases...) {
				k := key{nw.Name, m.Container, name}
				if !strings.HasPrefix(name, aliasPrefix) || seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, &agentv1.EdgeAlias{Network: nw.Name, Container: m.Container, Alias: name})
			}
		}
	}
	if len(out) > maxEdgeAliases {
		return nil, fmt.Errorf("more than %d hs-* names on the edge's networks", maxEdgeAliases)
	}
	sort.Slice(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if x.GetAlias() != y.GetAlias() {
			return x.GetAlias() < y.GetAlias()
		}
		if x.GetNetwork() != y.GetNetwork() {
			return x.GetNetwork() < y.GetNetwork()
		}
		return x.GetContainer() < y.GetContainer()
	})
	return out, nil
}
