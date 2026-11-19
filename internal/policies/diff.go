package policies

import (
	"encoding/json"
	"sort"
	"strings"
)

// Diff of two rendered policies for the reviewer (§7.3 "diff văn bản + diff rule có cấu trúc"): a line diff of the
// canonical documents and the grants added and removed (each grant as its canonical JSON). Both sides are rendered with
// the tables as they are now, so the diff shows what applying one instead of the other would change.

// maxDiffCells bounds the line diff (an LCS table of from × to lines); larger documents get the structured diff only.
const maxDiffCells = 4_000_000

// Ops of a DiffLine.
const (
	DiffSame    = "same"    // in both
	DiffRemoved = "removed" // only in the base
	DiffAdded   = "added"   // only in the version
)

// DiffLine is one line of the text diff.
type DiffLine struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// lineDiff is the LCS diff of two texts by line (nil, false when the documents are too large).
func lineDiff(from, to string) ([]DiffLine, bool) {
	a, b := splitLines(from), splitLines(to)
	if (len(a)+1)*(len(b)+1) > maxDiffCells {
		return nil, false
	}
	n, m := len(a), len(b)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	out := make([]DiffLine, 0, max(n, m))
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, DiffLine{Op: DiffSame, Text: a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, DiffLine{Op: DiffRemoved, Text: a[i]})
			i++
		default:
			out = append(out, DiffLine{Op: DiffAdded, Text: b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, DiffLine{Op: DiffRemoved, Text: a[i]})
	}
	for ; j < m; j++ {
		out = append(out, DiffLine{Op: DiffAdded, Text: b[j]})
	}
	return out, true
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// grantSet returns the canonical JSON of every grant of a rendered policy.
func grantSet(applied string) map[string]bool {
	out := map[string]bool{}
	if applied == "" {
		return out
	}
	var doc struct {
		Grants []json.RawMessage `json:"grants"`
	}
	if json.Unmarshal([]byte(applied), &doc) != nil {
		return out
	}
	for _, g := range doc.Grants {
		var v any
		if json.Unmarshal(g, &v) != nil {
			continue
		}
		b, err := json.Marshal(v) // map keys sorted: one form per grant
		if err == nil {
			out[string(b)] = true
		}
	}
	return out
}

// grantChanges are the grants only in to (added) and only in from (removed), sorted.
func grantChanges(from, to string) (added, removed []string) {
	a, b := grantSet(from), grantSet(to)
	for g := range b {
		if !a[g] {
			added = append(added, g)
		}
	}
	for g := range a {
		if !b[g] {
			removed = append(removed, g)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if added == nil {
		added = []string{}
	}
	if removed == nil {
		removed = []string{}
	}
	return added, removed
}
