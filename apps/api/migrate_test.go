package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func migrateEnv(m map[string]string) (func(string) string, []string) {
	var list []string
	for k, v := range m {
		list = append(list, k+"="+v)
	}
	return func(k string) string { return m[k] }, list
}

// TestMigrateCommand — `meshguard-api migrate` (job migrate / db-bootstrap of mg-app, P2-T16): usage and configuration
// errors (exit 2, a secret value in the environment refused without being repeated), then `up` and `status` on a
// database migrated like a deployment: idempotent, passwords of the six login roles set from the job's directory,
// state current; a missing role file fails before any password is set. bootstrap itself is covered by
// internal/store.TestDeploySteps (the superuser password of the test cluster is not handed to this package).
func TestMigrateCommand(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"down"}, {"up", "extra"}} {
		errb.Reset()
		if code := migrate(context.Background(), args, func(string) string { return "" }, nil, &out, &errb); code != 2 ||
			!strings.Contains(errb.String(), "usage:") {
			t.Errorf("%q: %d %q", args, code, errb.String())
		}
	}
	canary := strings.Join([]string{"hunter2", "CANARY"}, "-") // built at run time: no credential-like literal (gitleaks)
	getenv, environ := migrateEnv(map[string]string{"MG_DB_URL": "postgres://postgres:5432/meshguard",
		"MG_DB_MIGRATOR_PASSWORD": canary, "MG_DB_ROLE_PASSWORD_DIR": "/run/mg-migrate"})
	errb.Reset()
	if code := migrate(context.Background(), []string{"up"}, getenv, environ, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "MG_DB_MIGRATOR_PASSWORD_FILE") || strings.Contains(errb.String(), canary) {
		t.Fatalf("secret in the environment: %d %q", code, errb.String())
	}

	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	dir := t.TempDir()
	for _, r := range append([]string{store.MigratorRole}, store.LoginRoles...) {
		writeTestFile(t, filepath.Join(dir, r), pg.Password(r)+"\n")
	}
	vars := map[string]string{"MG_ENV": "ci", "MG_DB_URL": pg.URL(db), "MG_DB_MIGRATOR_PASSWORD_FILE": filepath.Join(dir, store.MigratorRole),
		"MG_DB_ROLE_PASSWORD_DIR": dir}
	for _, mode := range []string{"up", "up", "status"} {
		out.Reset()
		errb.Reset()
		getenv, environ := migrateEnv(vars)
		if code := migrate(context.Background(), []string{mode}, getenv, environ, &out, &errb); code != 0 {
			t.Fatalf("%s: %d\n%s%s", mode, code, out.String(), errb.String())
		}
		var res migrateResult
		if err := json.Unmarshal(out.Bytes(), &res); err != nil || !res.Current || res.State.SchemaVersion != res.State.LatestMigration {
			t.Fatalf("%s: %s (%v)", mode, out.String(), err)
		}
		if mode == "up" && strings.Join(res.PasswordsSet, ",") != strings.Join(store.LoginRoles, ",") {
			t.Errorf("up set %v", res.PasswordsSet)
		}
		for _, r := range store.LoginRoles {
			if strings.Contains(out.String()+errb.String(), pg.Password(r)) {
				t.Fatalf("%s: a password reached the output", mode)
			}
		}
	}
	missing := t.TempDir()
	writeTestFile(t, filepath.Join(missing, store.MigratorRole), pg.Password(store.MigratorRole)+"\n")
	vars["MG_DB_ROLE_PASSWORD_DIR"] = missing
	getenv, environ = migrateEnv(vars)
	errb.Reset()
	if code := migrate(context.Background(), []string{"up"}, getenv, environ, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "no password file") && !strings.Contains(errb.String(), "read password file") {
		t.Fatalf("missing role files: %d %q", code, errb.String())
	}
}
