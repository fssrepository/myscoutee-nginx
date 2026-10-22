// The gateway receives backend leases; it never probes a backend.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type lease struct {
	ready    bool
	received time.Time
}
type receiver struct {
	mu      sync.Mutex
	tokens  map[string]string
	states  map[string]map[string]lease
	now     func() time.Time
	ttl     time.Duration
	changed chan struct{}
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (s *receiver) receive(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/internal/runtime-status" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	service := r.Header.Get("X-MyScoutee-Service")
	token, known := s.tokens[service]
	if !known || token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body struct {
		Instance string `json:"instance"`
		Ready    *bool  `json:"ready"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || body.Ready == nil || !identifier.MatchString(body.Instance) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	states := s.states[service]
	if states == nil {
		states = map[string]lease{}
		s.states[service] = states
	}
	for id, v := range states {
		if now.Sub(v.received) >= s.ttl {
			delete(states, id)
		}
	}
	if _, exists := states[body.Instance]; !exists && len(states) >= 128 {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	states[body.Instance] = lease{*body.Ready, now}
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
	w.WriteHeader(http.StatusNoContent)
}

// A shell may supply an infrastructure-owned source at build time. The canonical
// Compose/E2E binary has no Kubernetes code, credential or runtime dependency.
var infrastructureSource func(context.Context) (statusSource, error)

type statusValue struct {
	Ready     bool  `json:"ready"`
	Known     bool  `json:"known"`
	CheckedAt int64 `json:"checkedAt"`
}
type statusSource interface {
	snapshot() (statusValue, time.Time, <-chan struct{})
}

func (s *receiver) snapshot() (statusValue, time.Time, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.changed == nil {
		s.changed = make(chan struct{})
	}
	now := s.now()
	ready := len(s.tokens) > 0
	var next time.Time
	for service := range s.tokens {
		up := false
		for _, v := range s.states[service] {
			expiry := v.received.Add(s.ttl)
			if v.ready && now.Before(expiry) {
				up = true
				if next.IsZero() || expiry.Before(next) {
					next = expiry
				}
			}
		}
		if !up {
			ready = false
		}
	}
	return statusValue{ready, true, now.Unix()}, next, s.changed
}
func (s *receiver) status(w http.ResponseWriter, r *http.Request) { serveStatus(s, w, r) }
func serveStatus(s statusSource, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/runtime-status" && r.URL.Path != "/api/runtime-status/events" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/api/runtime-status/events" {
		serveEvents(s, w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	value, _, _ := s.snapshot()
	json.NewEncoder(w).Encode(value)
}

func tokensFromEnvironment() (map[string]string, error) {
	tokens := map[string]string{}
	if raw := os.Getenv("MYSCOUTEE_RUNTIME_STATUS_TOKENS_JSON"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
			return nil, errors.New("invalid runtime-status token configuration")
		}
	} else {
		token := strings.TrimSpace(os.Getenv("MYSCOUTEE_RUNTIME_STATUS_TOKEN"))
		if token == "" {
			path := os.Getenv("MYSCOUTEE_RUNTIME_STATUS_TOKEN_FILE")
			if path == "" {
				return nil, errors.New("runtime-status credential is required")
			}
			data, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					return nil, err
				}
				bytes := make([]byte, 32)
				if _, err = rand.Read(bytes); err != nil {
					return nil, err
				}
				// Compose mounts this dedicated volume only in nginx and the backend.
				f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
				if openErr == nil {
					_, err = f.WriteString(hex.EncodeToString(bytes))
					if err == nil {
						err = f.Chmod(0444)
					}
					closeErr := f.Close()
					if err != nil {
						return nil, err
					}
					if closeErr != nil {
						return nil, closeErr
					}
				} else if !errors.Is(openErr, os.ErrExist) {
					return nil, openErr
				}
				data, err = os.ReadFile(path)
			}
			if err != nil {
				return nil, err
			}
			token = strings.TrimSpace(string(data))
		}
		tokens["profilemanagement"] = token
	}
	if len(tokens) == 0 {
		return nil, errors.New("expected at least one runtime-status service")
	}
	for service, token := range tokens {
		if !identifier.MatchString(service) || len(token) < 32 {
			return nil, errors.New("invalid runtime-status service credential")
		}
	}
	return tokens, nil
}

func main() {
	ctx := context.Background()
	var source statusSource
	var leases *receiver
	if infrastructureSource != nil {
		var err error
		source, err = infrastructureSource(ctx)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		tokens, err := tokensFromEnvironment()
		if err != nil {
			log.Fatal(err)
		}
		leases = &receiver{tokens: tokens, states: map[string]map[string]lease{}, now: time.Now, ttl: 20 * time.Second}
		source = leases
	}
	errors := make(chan error, 2)
	go func() {
		server := &http.Server{Addr: "127.0.0.1:9080", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveStatus(source, w, r) }), ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 4096}
		errors <- server.ListenAndServe()
	}()
	if leases != nil {
		go func() {
			server := &http.Server{Addr: ":9081", Handler: http.HandlerFunc(leases.receive), ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 4096}
			errors <- server.ListenAndServe()
		}()
	}
	log.Fatal(<-errors)
}
