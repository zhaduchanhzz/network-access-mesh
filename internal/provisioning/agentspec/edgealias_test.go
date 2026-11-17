package agentspec

import (
	"context"
	"fmt"
	"testing"
)

// TestEdgeAliases: only networks the edge is attached to are listed; every hs-* container name or alias of their
// members appears once (Docker reports an alias both as alias and as DNS name), sorted; other names and the networks
// without the edge are ignored; without Docker access the list is empty.
func TestEdgeAliases(t *testing.T) {
	h := testHost(t)
	inv := &fakeInventory{nets: []NetworkInfo{
		{Name: "mg-t-acme", Members: []Member{
			{Container: "mg-hs-acme", Aliases: []string{"hs-acme", "hs-acme", "mg-hs-acme", "0123456789ab"}},
			{Container: "mg-edge", Aliases: []string{"mg-edge"}},
		}},
		{Name: "mg-t-evil", Members: []Member{ // a second network of the edge holding the same alias
			{Container: "mg-hs-evil", Aliases: []string{"hs-evil"}},
			{Container: "rogue", Aliases: []string{"hs-acme"}},
			{Container: "mg-edge"},
		}},
		{Name: "mg-t-lone", Members: []Member{ // not attached to the edge: ignored
			{Container: "mg-hs-lone", Aliases: []string{"hs-lone"}},
			{Container: "other", Aliases: []string{"hs-acme"}},
		}},
		{Name: "mg-edge", Members: []Member{{Container: "mg-edge"}, {Container: "hs-named", Aliases: nil}}},
	}}
	g := &Guard{Host: h, Inventory: inv, Edge: "mg-edge"}
	got, err := g.EdgeAliases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, a := range got {
		s = append(s, fmt.Sprintf("%s %s %s", a.GetAlias(), a.GetNetwork(), a.GetContainer()))
	}
	want := []string{"hs-acme mg-t-acme mg-hs-acme", "hs-acme mg-t-evil rogue", "hs-evil mg-t-evil mg-hs-evil",
		"hs-named mg-edge hs-named"}
	if fmt.Sprint(s) != fmt.Sprint(want) {
		t.Fatalf("edge aliases\n got %v\nwant %v", s, want)
	}
	if got, err := (&Guard{Host: h, Edge: "mg-edge"}).EdgeAliases(context.Background()); err != nil || got != nil {
		t.Fatalf("without Docker access: %v %v", got, err)
	}
}
