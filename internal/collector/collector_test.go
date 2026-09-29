package collector

import (
	"context"
	"errors"
	"lightweight-security-monitoring/internal/domain"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
)

type recordingSink struct {
	mu     sync.Mutex
	events []domain.Event
}

func (s *recordingSink) Ingest(_ context.Context, e domain.Event) (*domain.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil, nil
}

func (s *recordingSink) snapshot() []domain.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domain.Event(nil), s.events...)
}

type countingRecorder struct {
	mu     sync.Mutex
	counts map[string]int
}

func (r *countingRecorder) RecordCollectorLine(collector, result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[collector+"/"+result]++
}

func (r *countingRecorder) get(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[key]
}

// runUntilIdle runs c inside the current synctest bubble until it has processed
// everything available and waits idle for new data, then stops it.
func runUntilIdle(t *testing.T, c Collector) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- c.Run(ctx) }()
	synctest.Wait()
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("collector stopped with %v", err)
	}
}

func TestAccessLogCollector_EndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "access.log")
		appendFile(t, path, strings.Join([]string{
			`203.0.113.7 - - [10/Oct/2026:13:55:36 +0000] "POST /login HTTP/1.1" 401 0 "-" "curl/8.0"`,
			`garbage`,
			`203.0.113.7 - - [10/Oct/2026:13:55:37 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"`,
		}, "\n")+"\n")

		sink := &recordingSink{}
		rec := &countingRecorder{counts: map[string]int{}}
		collectors, err := Build(Config{AccessLogs: []AccessLogConfig{{
			Name:        "nginx",
			Path:        path,
			FromStart:   true,
			Format:      "combined",
			FailedLogin: &FailedLoginConfig{Paths: []string{"/login"}},
		}}}, sink, rec, discardLogger)
		if err != nil {
			t.Fatal(err)
		}
		runUntilIdle(t, collectors[0])

		events := sink.snapshot()
		if len(events) != 2 {
			t.Fatalf("expected 2 events, got %d", len(events))
		}
		if events[0].EventType != domain.EventFailedLogin {
			t.Errorf("first event type = %s, want failed_login", events[0].EventType)
		}
		if events[1].Path != "/.env" || events[1].StatusCode != 404 {
			t.Errorf("unexpected second event %+v", events[1])
		}
		if rec.get("nginx/"+ResultIngested) != 2 || rec.get("nginx/"+ResultParseError) != 1 {
			t.Errorf("unexpected line metrics %v", rec.counts)
		}
	})
}

func TestBuild_ValidationErrors(t *testing.T) {
	cases := map[string]AccessLogConfig{
		"missing path":         {Format: "combined"},
		"unknown format":       {fileOptions: fileOptions{Path: "a.log"}, Format: "apache2"},
		"fields on combined":   {fileOptions: fileOptions{Path: "a.log"}, Format: "combined", Fields: map[string]string{"ip": "x"}},
		"unknown json field":   {fileOptions: fileOptions{Path: "a.log"}, Format: "json", Fields: map[string]string{"client": "x"}},
		"login without paths":  {fileOptions: fileOptions{Path: "a.log"}, Format: "combined", FailedLogin: &FailedLoginConfig{}},
		"login path w/o slash": {fileOptions: fileOptions{Path: "a.log"}, Format: "combined", FailedLogin: &FailedLoginConfig{Paths: []string{"login"}}},
		"custom json needs ip": {fileOptions: fileOptions{Path: "a.log"}, Format: "json", Fields: map[string]string{"ip": ""}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(Config{AccessLogs: []AccessLogConfig{cfg}}, &recordingSink{}, nil, discardLogger); err == nil {
				t.Error("expected an error")
			}
		})
	}

	dup := []AccessLogConfig{{Path: "a/access.log", Format: "combined"}, {Path: "b/access.log", Format: "combined"}}
	if _, err := Build(Config{AccessLogs: dup}, &recordingSink{}, nil, discardLogger); err == nil {
		t.Error("expected duplicate default names to be rejected")
	}
}
