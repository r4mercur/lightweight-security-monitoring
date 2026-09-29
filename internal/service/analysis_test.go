package service_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/metrics"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
)

// fakeAnalyzer answers with result/err after an optional delay or block.
type fakeAnalyzer struct {
	result domain.AIAnalysis
	err    error
	block  chan struct{} // if set, Analyze waits until it is closed or ctx ends

	mu    sync.Mutex
	calls int
}

func (f *fakeAnalyzer) Provider() string { return "fake" }
func (f *fakeAnalyzer) Model() string    { return "fake-1" }
func (f *fakeAnalyzer) Analyze(ctx context.Context, _ domain.Alert, _ domain.Event) (domain.AIAnalysis, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return domain.AIAnalysis{}, ctx.Err()
		}
	}
	return f.result, f.err
}

func (f *fakeAnalyzer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type analysisSetup struct {
	ingestion *service.IngestionService
	store     *repository.MemoryStore
	queue     *service.AnalysisQueue
	cancel    context.CancelFunc
	done      chan struct{}
}

func newAnalysisSetup(t *testing.T, analyzer service.Analyzer, cfg service.AnalysisConfig, start bool) *analysisSetup {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := repository.NewMemoryStore()
	queue, err := service.NewAnalysisQueue(analyzer, store, cfg, metrics.NewMetrics(), logger)
	if err != nil {
		t.Fatal(err)
	}
	s := &analysisSetup{
		ingestion: service.NewIngestionService(store, store, newEngine(t), queue, metrics.NewMetrics(), logger),
		store:     store,
		queue:     queue,
		done:      make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(t.Context())
	s.cancel = cancel
	if start {
		go func() { queue.Run(ctx); close(s.done) }()
	} else {
		close(s.done)
	}
	t.Cleanup(func() { cancel(); <-s.done })
	return s
}

// alertFor ingests an event that triggers SensitivePath (medium) from ip.
func (s *analysisSetup) alertFor(t *testing.T, ip string) *domain.Alert {
	t.Helper()
	alert, err := s.ingestion.Ingest(t.Context(), domain.Event{IP: ip, EventType: domain.EventHTTPRequest, Path: "/.env"})
	if err != nil || alert == nil {
		t.Fatalf("expected an alert, got %v, %v", alert, err)
	}
	return alert
}

// expectStatus waits until the workers are idle (synctest.Wait) and checks the
// stored alert's analysis status.
func (s *analysisSetup) expectStatus(t *testing.T, ip, status string) *domain.AIAnalysis {
	t.Helper()
	synctest.Wait()
	res, _ := s.store.ListAlerts(t.Context(), repository.ListQuery{IP: ip, Limit: 1})
	if len(res.Items) != 1 || res.Items[0].AIAnalysis == nil || res.Items[0].AIAnalysis.Status != status {
		t.Fatalf("expected analysis status %q, stored alert: %+v", status, res.Items)
	}
	return res.Items[0].AIAnalysis
}

// The queue tests run in synctest bubbles: synctest.Wait returns once every
// worker is blocked, so no polling or sleeping is needed, and a worker that
// does not stop on shutdown fails the test.

func TestAnalysisQueue_CompletesInBackground(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		analyzer := &fakeAnalyzer{
			result: domain.AIAnalysis{Verdict: "malicious", Confidence: "high", Category: "reconnaissance", Summary: "Probe for secrets."},
			block:  make(chan struct{}),
		}
		s := newAnalysisSetup(t, analyzer, service.AnalysisConfig{}, true)

		// Ingest returns immediately although the analyzer is still blocked.
		alert := s.alertFor(t, "10.9.1.1")
		if alert.AIAnalysis == nil || alert.AIAnalysis.Status != domain.AIStatusPending || alert.AIAnalysis.Provider != "fake" {
			t.Fatalf("expected a pending analysis on the returned alert, got %+v", alert.AIAnalysis)
		}
		s.expectStatus(t, "10.9.1.1", domain.AIStatusPending)

		close(analyzer.block)
		got := s.expectStatus(t, "10.9.1.1", domain.AIStatusCompleted)
		if got.Verdict != "malicious" || got.Model != "fake-1" || got.AnalyzedAt == nil {
			t.Errorf("unexpected stored analysis %+v", got)
		}
		// The alert returned earlier is not modified afterwards.
		if alert.AIAnalysis.Status != domain.AIStatusPending {
			t.Error("returned alert was mutated by the worker")
		}
		if alert.Severity != domain.SeverityMedium {
			t.Error("severity must never be changed by the analysis")
		}
	})
}

func TestAnalysisQueue_FailuresAndRefusals(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"provider error": {errors.New("anthropic API returned 529: overloaded"), domain.AIStatusFailed},
		"refusal":        {fmt.Errorf("%w (category cyber)", domain.ErrAIRefused), domain.AIStatusRefused},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newAnalysisSetup(t, &fakeAnalyzer{err: tc.err}, service.AnalysisConfig{}, true)
				s.alertFor(t, "10.9.2.1")
				got := s.expectStatus(t, "10.9.2.1", tc.want)
				if got.Error != tc.err.Error() || got.Verdict != "" {
					t.Errorf("unexpected stored analysis %+v", got)
				}
			})
		})
	}
}

func TestAnalysisQueue_FullQueueSkips(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Workers not started: the queue fills up after one alert.
		s := newAnalysisSetup(t, &fakeAnalyzer{}, service.AnalysisConfig{QueueSize: 1}, false)
		s.alertFor(t, "10.9.3.1")
		s.alertFor(t, "10.9.3.2")

		s.expectStatus(t, "10.9.3.1", domain.AIStatusPending)
		got := s.expectStatus(t, "10.9.3.2", domain.AIStatusSkipped)
		if got.Error != "analysis queue full" {
			t.Errorf("unexpected stored analysis %+v", got)
		}
		if s.queue.Len() != 1 {
			t.Errorf("queue length = %d, want 1", s.queue.Len())
		}
	})
}

func TestAnalysisQueue_MinSeverity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		analyzer := &fakeAnalyzer{}
		s := newAnalysisSetup(t, analyzer, service.AnalysisConfig{MinSeverity: domain.SeverityHigh}, true)

		alert := s.alertFor(t, "10.9.4.1") // medium
		if alert.AIAnalysis != nil {
			t.Errorf("medium alert must not be analyzed with min severity high, got %+v", alert.AIAnalysis)
		}
		synctest.Wait()
		if n := analyzer.callCount(); n != 0 {
			t.Errorf("analyzer called %d times", n)
		}
	})
}

func TestAnalysisQueue_ShutdownLeavesPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		analyzer := &fakeAnalyzer{block: make(chan struct{})}
		s := newAnalysisSetup(t, analyzer, service.AnalysisConfig{}, true)
		s.alertFor(t, "10.9.5.1")
		synctest.Wait() // the worker is now inside Analyze

		s.cancel()
		<-s.done
		s.expectStatus(t, "10.9.5.1", domain.AIStatusPending)
		if n := analyzer.callCount(); n != 1 {
			t.Errorf("analyzer called %d times, want 1", n)
		}
	})
}

func TestNewAnalysisQueue_Validation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for name, cfg := range map[string]service.AnalysisConfig{
		"negative workers": {Workers: -1},
		"negative queue":   {QueueSize: -5},
		"invalid severity": {MinSeverity: "urgent"},
	} {
		if _, err := service.NewAnalysisQueue(&fakeAnalyzer{}, repository.NewMemoryStore(), cfg, nil, logger); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
