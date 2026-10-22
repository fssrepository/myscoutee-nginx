package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStatusStreamLeaseExpiryAndRecovery(t *testing.T) {
	s := &receiver{tokens: map[string]string{"a": "token"}, states: map[string]map[string]lease{}, now: time.Now, ttl: 150 * time.Millisecond}
	server := httptest.NewServer(http.HandlerFunc(s.status))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/runtime-status/events", nil)
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	events := make(chan statusValue, 10)
	go func() {
		scanner := bufio.NewScanner(response.Body)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "data: ") {
				var v statusValue
				json.Unmarshal([]byte(strings.TrimPrefix(scanner.Text(), "data: ")), &v)
				events <- v
			}
		}
	}()
	check := func(ready bool) {
		t.Helper()
		select {
		case v := <-events:
			if v.Ready != ready {
				t.Fatalf("got %+v want ready=%v", v, ready)
			}
		case <-ctx.Done():
			t.Fatal("missing stream transition")
		}
	}
	send := func() {
		r := httptest.NewRequest("POST", "/internal/runtime-status", strings.NewReader(`{"instance":"one","ready":true}`))
		r.Header.Set("X-MyScoutee-Service", "a")
		r.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		s.receive(w, r)
		if w.Code != 204 {
			t.Fatal(w.Code)
		}
	}
	check(false)
	send()
	check(true)
	send()       // an unchanged heartbeat must not produce another status event
	check(false) // deadline expires even without another incoming heartbeat
	send()
	check(true)
	cancel()
}
