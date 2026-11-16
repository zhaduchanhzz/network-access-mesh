package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generate_204":
			w.WriteHeader(http.StatusNoContent)
		case "/redirect":
			http.Redirect(w, r, "/generate_204", http.StatusPermanentRedirect)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"default status 204", []string{srv.URL + "/generate_204"}, 0},
		{"explicit status", []string{srv.URL + "/missing", "404"}, 0},
		{"unexpected status", []string{srv.URL + "/missing"}, 1},
		{"redirect is not followed", []string{srv.URL + "/redirect"}, 1},
		{"connection refused", []string{"http://127.0.0.1:1/generate_204"}, 1},
		{"no arguments", nil, 2},
		{"bad status argument", []string{srv.URL, "abc"}, 2},
		{"too many arguments", []string{srv.URL, "204", "x"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args); got != tc.want {
				t.Fatalf("run(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}
