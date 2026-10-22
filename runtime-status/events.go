package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

var eventClients atomic.Int32

// A client gets an initial snapshot, state changes, and transport-only pings.
// Lease expiration is a deadline, not a periodic health poll.
func serveEvents(s statusSource, w http.ResponseWriter, r *http.Request) {
	if eventClients.Add(1) > 256 {
		eventClients.Add(-1)
		http.Error(w, "status stream capacity", http.StatusServiceUnavailable)
		return
	}
	defer eventClients.Add(-1)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	controller := http.NewResponseController(w)
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	var previous statusValue
	initial := true
	write := func(event string, value statusValue) bool {
		controller.SetWriteDeadline(time.Now().Add(2 * time.Second))
		b, _ := json.Marshal(value)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		return controller.Flush() == nil
	}
	for {
		value, expiry, changed := s.snapshot()
		if initial || previous.Ready != value.Ready || previous.Known != value.Known {
			if !write("status", value) {
				return
			}
			previous = value
			initial = false
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if !expiry.IsZero() {
			timer = time.NewTimer(max(time.Until(expiry), 0))
			timeout = timer.C
		}
		stop := false
		select {
		case <-r.Context().Done():
			stop = true
		case <-changed:
		case <-timeout:
		case <-ping.C:
			v, _, _ := s.snapshot()
			if !write("ping", v) {
				stop = true
			}
		}
		if timer != nil {
			timer.Stop()
		}
		if stop {
			return
		}
	}
}
