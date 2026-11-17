package problem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

const canary = "CANARY-5e1d0b7a"

// specCodes reads the ProblemCode schema of api/openapi.yaml: the enum and the "`code`, … (status)" pairs of its
// description, which restate the table of §13.1.
func specCodes(t *testing.T) (enum []string, status map[string]int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	start := slices.Index(lines, "    ProblemCode:")
	if start < 0 {
		t.Fatal("ProblemCode schema not found in api/openapi.yaml")
	}
	var desc []string
	inDesc, inEnum := false, false
scan:
	for _, ln := range lines[start+1:] {
		trimmed := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(trimmed, "description:"):
			inDesc = true
		case trimmed == "enum:":
			inDesc, inEnum = false, true
		case inEnum && strings.HasPrefix(trimmed, "- "):
			enum = append(enum, strings.TrimPrefix(trimmed, "- "))
		case inEnum:
			break scan
		case inDesc:
			desc = append(desc, trimmed)
		}
	}
	if len(desc) < 2 {
		t.Fatalf("ProblemCode description not found: %v", desc)
	}
	status = map[string]int{}
	tick := regexp.MustCompile("`([a-z_]+)`")
	num := regexp.MustCompile(`^\((\d{3})`)
	for _, part := range strings.Split(strings.Join(desc[1:], " "), "·") {
		before, after, ok := strings.Cut(part, "(")
		m := num.FindStringSubmatch("(" + after)
		if !ok || m == nil {
			t.Fatalf("cannot parse ProblemCode description part %q", part)
		}
		st, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range tick.FindAllStringSubmatch(before, -1) {
			status[c[1]] = st
		}
	}
	return enum, status
}

// TestCatalogFollowsSpec: every code of the spec has the status §13.1 gives it; the catalog adds only
// CodeNotImplemented, which is pending in the spec.
func TestCatalogFollowsSpec(t *testing.T) {
	enum, status := specCodes(t)
	if len(enum) < 15 || len(status) != len(enum) {
		t.Fatalf("spec enum %v vs described codes %v", enum, status)
	}
	for _, code := range enum {
		want, described := status[code]
		e, ok := catalog[gen.ProblemCode(code)]
		if !described || !ok || e.status != want {
			t.Errorf("code %s: spec status %d (described %v), catalog %+v (present %v)", code, want, described, e, ok)
		}
		if !gen.ProblemCode(code).Valid() {
			t.Errorf("code %s of the spec is not a generated enum value", code)
		}
	}
	for code := range catalog {
		if !slices.Contains(enum, string(code)) && code != CodeNotImplemented {
			t.Errorf("catalog code %s is not in the spec enum", code)
		}
	}
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, rec.Body.String())
	}
	return body
}

// TestWriteEveryCode: shape, status and headers of the problem of each code.
func TestWriteEveryCode(t *testing.T) {
	ctx := requestid.With(context.Background(), "rid-7")
	for code, ent := range catalog {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/tenants/x?code="+canary, nil)
		Write(rec, req, New(code, "some detail"))

		if rec.Code != ent.status {
			t.Errorf("%s: status %d, want %d", code, rec.Code, ent.status)
		}
		h := rec.Header()
		if h.Get("Content-Type") != ContentType || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: headers %v", code, h)
		}
		body := decode(t, rec)
		want := map[string]any{
			"type": TypePrefix + string(code), "title": ent.title, "status": float64(ent.status), "code": string(code),
			"request_id": "rid-7", "instance": "/api/v1/tenants/x", "detail": "some detail",
		}
		if len(body) != len(want) {
			t.Errorf("%s: fields %v, want %v", code, body, want)
		}
		for k, v := range want {
			if body[k] != v {
				t.Errorf("%s: %s = %v, want %v", code, k, body[k], v)
			}
		}
		if strings.Contains(rec.Body.String(), canary) {
			t.Errorf("%s: query string echoed in the problem: %s", code, rec.Body.String())
		}
	}
}

func TestWriteDetails(t *testing.T) {
	// Retry-After is rounded up to whole seconds.
	rec := httptest.NewRecorder()
	Write(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil),
		&Error{Code: gen.ProblemCodeRateLimited, RetryAfter: 1500 * time.Millisecond})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Errorf("rate_limited: %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if body := decode(t, rec); body["detail"] != nil || body["errors"] != nil {
		t.Errorf("empty detail/errors must be omitted: %v", body)
	}

	// An unknown code or a nil error becomes internal_error; the request id falls back to the response header.
	for _, e := range []*Error{{Code: "made_up", Detail: "leak " + canary}, nil} {
		rec = httptest.NewRecorder()
		rec.Header().Set(requestid.Header, "rid-hdr")
		Write(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil), e)
		body := decode(t, rec)
		if rec.Code != 500 || body["code"] != "internal_error" || body["request_id"] != "rid-hdr" || strings.Contains(rec.Body.String(), canary) {
			t.Errorf("unknown code: %d %v", rec.Code, body)
		}
	}

	// The cause stays out of the response; Error() and Unwrap() expose it to the internal log.
	cause := errors.New("db: " + canary)
	e := Internal(cause)
	rec = httptest.NewRecorder()
	Write(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil), e)
	if strings.Contains(rec.Body.String(), canary) {
		t.Errorf("cause leaked: %s", rec.Body.String())
	}
	if !errors.Is(e, cause) || !strings.Contains(e.Error(), canary) || e.Status() != 500 {
		t.Errorf("Error()=%q Unwrap/Status wrong", e.Error())
	}
	if got := NotImplemented("ListDevices"); got.Status() != http.StatusNotImplemented || !strings.Contains(got.Detail, "ListDevices") {
		t.Errorf("NotImplemented: %+v", got)
	}
}

func TestSeconds(t *testing.T) {
	for d, want := range map[time.Duration]int64{-time.Second: 0, 0: 0, time.Nanosecond: 1, time.Second: 1, 1001 * time.Millisecond: 2, time.Minute: 60} {
		if got := Seconds(d); got != want {
			t.Errorf("Seconds(%v) = %d, want %d", d, got, want)
		}
	}
}

// fields writes e and returns the errors[] of the body, failing if the canary appears anywhere in it.
func fields(t *testing.T, e *Error) []gen.FieldError {
	t.Helper()
	rec := httptest.NewRecorder()
	Write(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/api/v1/x", nil), e)
	if rec.Code != http.StatusUnprocessableEntity || strings.Contains(rec.Body.String(), canary) {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var p gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Errors == nil || p.Code != gen.ProblemCodeValidationFailed {
		t.Fatalf("problem %+v: %v", p, err)
	}
	return *p.Errors
}

// TestFromBindError: every binding error of the generated router names the parameter, never its value.
func TestFromBindError(t *testing.T) {
	inner := errors.New("error unmarshaling '" + canary + "' text as *uuid.UUID")
	cases := []struct {
		err         error
		field, code string
	}{
		{&gen.InvalidParamFormatError{ParamName: "tenantId", Err: inner}, "tenantId", "invalid_format"},
		{&gen.RequiredParamError{ParamName: "scope"}, "scope", "required"},
		{&gen.RequiredHeaderError{ParamName: "Idempotency-Key", Err: inner}, "Idempotency-Key", "required"},
		{&gen.TooManyValuesForParamError{ParamName: "limit", Count: 2}, "limit", "too_many_values"},
		{&gen.UnmarshalingParamError{ParamName: "filter", Err: inner}, "filter", "invalid_format"},
		{&gen.UnescapedCookieParamError{ParamName: "__Host-mg_authreq", Err: inner}, "__Host-mg_authreq", "invalid_format"},
		{fmt.Errorf("wrapped: %w", &gen.InvalidParamFormatError{ParamName: "deviceId", Err: inner}), "deviceId", "invalid_format"},
		{errors.New("something else " + canary), "request", "invalid"},
	}
	for _, c := range cases {
		e := FromBindError(c.err)
		if e.Cause != nil {
			t.Errorf("%v: the raw binding error must not be kept as Cause", c.err)
		}
		f := fields(t, e)
		if len(f) != 1 || f[0].Field != c.field || f[0].Code != c.code {
			t.Errorf("%T: errors %+v, want field %s code %s", c.err, f, c.field, c.code)
		}
	}
}

// TestFromBodyError uses the real decoding errors of encoding/json and http.MaxBytesReader.
func TestFromBodyError(t *testing.T) {
	decodeErr := func(body string, v any) error {
		return json.NewDecoder(strings.NewReader(body)).Decode(v)
	}
	tooLarge := func() error {
		r := http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(strings.NewReader(`{"given_name":"`+strings.Repeat("a", 100)+canary+`"}`)), 64)
		return json.NewDecoder(r).Decode(&gen.DeviceRename{})
	}
	cases := []struct {
		name        string
		err         error
		field, code string
	}{
		{"empty", decodeErr("", &gen.DeviceRename{}), "body", "required"},
		{"truncated", decodeErr(`{"given_name": "`+canary, &gen.DeviceRename{}), "body", "invalid_json"},
		{"syntax", decodeErr(`{given_name: `+canary+`}`, &gen.DeviceRename{}), "body", "invalid_json"},
		{"wrong type", decodeErr(`{"given_name": 12345678}`, &gen.DeviceRename{}), "given_name", "invalid_type"},
		// a map key chosen by the client is never echoed (the path is "x" or falls back to "body")
		{"map key from the client", decodeErr(`{"x": {"`+canary+`": "s"}}`, &map[string]map[string]int{}), "", "invalid_type"},
		{"too large", tooLarge(), "body", "too_large"},
		{"other", fmt.Errorf("can't decode JSON body: %w", errors.New("parsing time "+canary)), "body", "invalid_value"},
	}
	for _, c := range cases {
		if c.err == nil {
			t.Fatalf("%s: decoding did not fail", c.name)
		}
		f := fields(t, FromBodyError(fmt.Errorf("can't decode JSON body: %w", c.err)))
		if len(f) != 1 || (c.field != "" && f[0].Field != c.field) || f[0].Code != c.code {
			t.Errorf("%s (%v): errors %+v, want field %s code %s", c.name, c.err, f, c.field, c.code)
		}
	}
}
