package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLeases(t *testing.T) {
	now := time.Unix(1000, 0)
	s := &receiver{tokens: map[string]string{"a": "a-token", "b": "b-token"}, states: map[string]map[string]lease{}, now: func() time.Time { return now }, ttl: 20 * time.Second}
	send := func(service, token, body string, want int) {
		t.Helper()
		r := httptest.NewRequest("POST", "/internal/runtime-status", strings.NewReader(body))
		r.Header.Set("X-MyScoutee-Service", service)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.receive(w, r)
		if w.Code != want {
			t.Fatalf("send: %d != %d", w.Code, want)
		}
	}
	check := func(want bool) {
		t.Helper()
		w := httptest.NewRecorder()
		s.status(w, httptest.NewRequest("GET", "/api/runtime-status", nil))
		var v struct {
			Ready     bool
			CheckedAt int64
		}
		json.Unmarshal(w.Body.Bytes(), &v)
		if v.Ready != want || v.CheckedAt != now.Unix() {
			t.Fatalf("status %s", w.Body.String())
		}
		if strings.Contains(w.Body.String(), "token") {
			t.Fatal("credential leak")
		}
	}
	check(false)
	send("a", "b-token", `{"instance":"one","ready":true}`, 401)
	send("a", "a-token", `{"instance":"one","ready":true}`, 204)
	check(false)
	send("b", "b-token", `{"instance":"two","ready":true}`, 204)
	check(true)
	now = now.Add(15 * time.Second)
	check(true) // two missed five-second publications still fit within the lease
	now = now.Add(5 * time.Second)
	check(false)
	send("a", "a-token", `{"instance":"new","ready":true}`, 204)
	send("b", "b-token", `{"instance":"two","ready":true}`, 204)
	check(true)
	send("a", "a-token", `{"instance":"one","ready":false}`, 204)
	check(true) // old pod cannot overwrite replacement
	send("a", "a-token", `{"instance":"new","ready":false}`, 204)
	check(false)
	for _, body := range []string{`{"instance":"one"}`, `{"instance":"../x","ready":true}`, `{"instance":"one","ready":true,"secret":"x"}`, `{"instance":"one","ready":true} {}`, strings.Repeat("x", 2048)} {
		send("a", "a-token", body, 400)
	}
	s.states = map[string]map[string]lease{}
	check(false) // gateway restart needs new leases
	w := httptest.NewRecorder()
	s.status(w, httptest.NewRequest(http.MethodPost, "/api/runtime-status", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
