package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// TestCanaryCredentialsNeverLeak is the "canary secret" test of §25.1 rule 9 for the adapter: the instance API key,
// the edge token and the credentials Headscale returns (new API key, pre-auth key) must never appear in a log
// line, an error string, or any formatting of the values that carry them — even when Headscale echoes the request
// headers back in an error message.
func TestCanaryCredentialsNeverLeak(t *testing.T) {
	const (
		apiCanary  = "CANARYSECRETAPI"
		edgeCanary = "CANARYEDGE"
		newCanary  = "CANARYNEWKEY"
		pakCanary  = "CANARYPAK"
	)
	apiKey := "hskey-" + "api-" + "CanaryPfx123" + "-" + apiCanary + strings.Repeat("9", 40)
	edgeToken := edgeCanary + strings.Repeat("7", 30)
	newKey := "hskey-" + "api-" + "NewPfx123456" + "-" + newCanary + strings.Repeat("8", 40)
	pak := "hskey-" + "auth-" + "PakPfx123456" + "-" + pakCanary + strings.Repeat("6", 40)

	var logs bytes.Buffer
	h := newHarness(t, Options{Logger: logx.New(&logs, slog.LevelDebug, "test"), Retry: RetryPolicy{Attempts: 1}})
	h.edge.set(func(f *fakeEdge) { f.apiKey, f.token = apiKey, edgeToken })
	h.loc.t.APIKey, h.loc.t.EdgeToken = NewSecret(apiKey), NewSecret(edgeToken)

	echo := func(r *http.Request) string {
		return "debug auth=" + r.Header.Get("Authorization") + " token=" + r.Header.Get(HeaderEdgeToken)
	}
	h.edge.onFunc("GET", "/api/v1/node/1", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(gw(2, echo(r))))
	})
	h.edge.onFunc("GET", "/api/v1/user", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(502)
		_, _ = w.Write([]byte(echo(r))) // non-JSON
	})
	h.edge.on("POST", "/api/v1/apikey", 200, `{"apiKey":"`+newKey+`"}`)
	h.edge.on("POST", "/api/v1/preauthkey", 200, `{"preAuthKey":{"id":"1", "key":"`+pak+`", "aclTags":["tag:ci"], "expiration":"2026-11-17T08:10:00Z"}}`)

	inst := h.instance(t)
	ctx := context.Background()
	var texts []string
	_, err := inst.GetNode(ctx, 1)
	texts = append(texts, err.Error(), fmt.Sprintf("%+v", err))
	_, err = inst.ListUsers(ctx, UserFilter{})
	texts = append(texts, err.Error(), fmt.Sprintf("%#v", err))

	key, err := inst.CreateAPIKey(ctx, h.clk.t.Add(time.Hour))
	if err != nil || key.Reveal() != newKey {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	j, _ := json.Marshal(map[string]any{"key": key})
	texts = append(texts, fmt.Sprintf("%v %s %+v %#v %q %x", key, key, key, key, key, key), string(j))
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("returned key", "value", key)

	p, err := inst.CreatePreAuthKey(ctx, PreAuthKeyOpts{Tags: []string{"tag:ci"}, Expiration: h.clk.t.Add(10 * time.Minute)})
	if err != nil || p.Key.Reveal() != pak || p.KeyPrefix != "PakPfx123456" {
		t.Fatalf("CreatePreAuthKey: %v %+v", err, p.KeyPrefix)
	}
	j, _ = json.Marshal(p)
	texts = append(texts, fmt.Sprintf("%v %+v %#v", p, p, p), string(j))

	tg := h.loc.t
	j, _ = json.Marshal(tg)
	texts = append(texts, fmt.Sprintf("%v %+v %#v", tg, tg, tg), string(j))
	texts = append(texts, logs.String())

	all := strings.Join(texts, "\n")
	for _, c := range []string{apiCanary, edgeCanary, newCanary, pakCanary} {
		if strings.Contains(all, c) {
			t.Fatalf("canary %s leaked:\n%s", c, all)
		}
	}
	if !strings.Contains(logs.String(), "headscale call") || !strings.Contains(all, logx.Redacted) {
		t.Fatalf("expected call logs and redaction markers:\n%s", logs.String())
	}
}
