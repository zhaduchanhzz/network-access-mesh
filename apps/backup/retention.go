package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// setFileRE matches the files of a backup set: <target>-<YYYYMMDDTHHMMSSZ>-<label>.<part>.
var setFileRE = regexp.MustCompile(`^(postgres|idp|edge)-([0-9]{8}T[0-9]{6}Z)-(scheduled|pre-migration|manual)\.` +
	`(globals\.sql\.age|pgdump\.age|tar\.age|manifest\.json)$`)

type backupSet struct {
	id, label string
	at        time.Time
	files     []string
	complete  bool // has its manifest (written last)
}

// scanSets lists the backup sets of target in dir. Only regular files whose names match setFileRE count: nothing
// else in the directory is ever touched.
func scanSets(dir, target string) map[string]*backupSet {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	sets := map[string]*backupSet{}
	for _, e := range entries {
		m := setFileRE.FindStringSubmatch(e.Name())
		if m == nil || m[1] != target || !e.Type().IsRegular() {
			continue
		}
		at, err := time.Parse("20060102T150405Z", m[2])
		if err != nil {
			continue
		}
		id := strings.TrimSuffix(e.Name(), "."+m[4])
		s := sets[id]
		if s == nil {
			s = &backupSet{id: id, label: m[3], at: at}
			sets[id] = s
		}
		s.files = append(s.files, e.Name())
		s.complete = s.complete || m[4] == PartManifest
	}
	return sets
}

// removeIncomplete deletes what an interrupted run left (called under the lock, before a new run): partial files
// and sets without a manifest.
func removeIncomplete(dir string, log *slog.Logger) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(n, ".") && (strings.HasSuffix(n, ".partial") || strings.HasSuffix(n, ".tmp")) {
			if os.Remove(filepath.Join(dir, n)) == nil {
				log.Warn("removed a leftover of an interrupted run", "file", n)
			}
		}
	}
	for _, target := range []string{TargetPostgres, TargetIdP, TargetEdge} {
		for _, s := range scanSets(dir, target) {
			if s.complete {
				continue
			}
			for _, f := range s.files {
				if os.Remove(filepath.Join(dir, f)) == nil {
					log.Warn("removed an incomplete backup set", "file", f)
				}
			}
		}
	}
}

// applyRetention deletes the complete sets of the target that the policy no longer keeps and returns the removed
// file names. Policy (§17.1, documented in the backup runbook):
//   - scheduled: keep every set younger than KeepDays, and always the KeepMin newest;
//   - pre-migration and manual: keep the KeepOnDemand newest of each label (never removed by age).
//
// It runs only after a successful backup, so a failing service never erodes the sets it already has.
func applyRetention(c *Config, now time.Time) []string {
	byLabel := map[string][]*backupSet{}
	for _, s := range scanSets(c.Dest, c.Target) {
		if s.complete {
			byLabel[s.label] = append(byLabel[s.label], s)
		}
	}
	var removed []string
	cutoff := now.Add(-time.Duration(c.KeepDays) * 24 * time.Hour)
	for label, sets := range byLabel {
		sort.Slice(sets, func(i, j int) bool { return sets[i].at.After(sets[j].at) })
		for i, s := range sets {
			keep := i < c.KeepOnDemand
			if label == LabelScheduled {
				keep = i < c.KeepMin || !s.at.Before(cutoff)
			}
			if keep {
				continue
			}
			sort.Slice(s.files, func(a, b int) bool { // manifest first: a crash midway leaves an incomplete set, not a lie
				return strings.HasSuffix(s.files[a], PartManifest) && !strings.HasSuffix(s.files[b], PartManifest)
			})
			for _, f := range s.files {
				if os.Remove(filepath.Join(c.Dest, f)) == nil {
					removed = append(removed, f)
				}
			}
		}
	}
	sort.Strings(removed)
	return removed
}
