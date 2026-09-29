package service

import (
	"context"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"log/slog"
	"sync"
	"time"
)

// Analyzer is the contract for AI-based alert analysis (implemented by package ai).
type Analyzer interface {
	Analyze(ctx context.Context, alert domain.Alert, event domain.Event) (domain.AIAnalysis, error)
	Provider() string
	Model() string
}

// AnalysisRecorder records AI analysis metrics.
type AnalysisRecorder interface {
	RecordAIAnalysis(provider, result string, duration time.Duration)
}

// AnalysisConfig tunes the analysis queue.
type AnalysisConfig struct {
	Workers     int             // parallel analyses, default 2
	QueueSize   int             // waiting alerts, default 100; more are skipped
	MinSeverity domain.Severity // alerts below are not analyzed, default low (all)
}

// AnalysisQueue analyzes alerts in the background so that a slow or
// unavailable model never delays detection. Alerts are stored immediately with
// status "pending"; workers attach the result when it is available.
type AnalysisQueue struct {
	analyzer    Analyzer
	alerts      repository.AlertRepository
	jobs        chan analysisJob
	workers     int
	minSeverity domain.Severity
	metrics     AnalysisRecorder
	logger      *slog.Logger
}

type analysisJob struct {
	alert domain.Alert
	event domain.Event
}

// NewAnalysisQueue creates a queue; call Run to start the workers.
func NewAnalysisQueue(analyzer Analyzer, alerts repository.AlertRepository, cfg AnalysisConfig, metrics AnalysisRecorder, logger *slog.Logger) (*AnalysisQueue, error) {
	if cfg.Workers == 0 {
		cfg.Workers = 2
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 100
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = domain.SeverityLow
	}
	switch {
	case cfg.Workers < 1:
		return nil, errors.New("workers must be at least 1")
	case cfg.QueueSize < 1:
		return nil, errors.New("queue size must be at least 1")
	case !cfg.MinSeverity.Valid():
		return nil, fmt.Errorf("invalid minimum severity %q (use low, medium, high or critical)", cfg.MinSeverity)
	}
	return &AnalysisQueue{
		analyzer:    analyzer,
		alerts:      alerts,
		jobs:        make(chan analysisJob, cfg.QueueSize),
		workers:     cfg.Workers,
		minSeverity: cfg.MinSeverity,
		metrics:     metrics,
		logger:      logger.With(slog.String("provider", analyzer.Provider()), slog.String("model", analyzer.Model())),
	}, nil
}

// Pending returns the analysis state to store with a new alert, or nil if the
// alert is below the minimum severity and will not be analyzed.
func (q *AnalysisQueue) Pending(alert domain.Alert) *domain.AIAnalysis {
	if alert.Severity.Rank() < q.minSeverity.Rank() {
		return nil
	}
	return q.state(domain.AIStatusPending, "")
}

// Submit queues a stored alert for analysis without blocking. When the queue
// is full the alert is marked as skipped.
func (q *AnalysisQueue) Submit(ctx context.Context, alert domain.Alert, event domain.Event) {
	select {
	case q.jobs <- analysisJob{alert: alert, event: event}:
	default:
		q.store(ctx, alert, *q.state(domain.AIStatusSkipped, "analysis queue full"))
		q.record(domain.AIStatusSkipped, 0)
		q.logger.WarnContext(ctx, "AI analysis skipped, queue full", slog.String("alert_id", alert.ID))
	}
}

// Len returns the number of alerts waiting for analysis.
func (q *AnalysisQueue) Len() int { return len(q.jobs) }

// Run processes the queue until ctx is cancelled. Analyses interrupted by the
// shutdown stay "pending".
func (q *AnalysisQueue) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for range q.workers {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-q.jobs:
					q.process(ctx, job)
				}
			}
		})
	}
	wg.Wait()
}

func (q *AnalysisQueue) process(ctx context.Context, job analysisJob) {
	start := time.Now()
	result, err := q.analyzer.Analyze(ctx, job.alert, job.event)
	if ctx.Err() != nil {
		return
	}

	switch {
	case errors.Is(err, domain.ErrAIRefused):
		result = *q.state(domain.AIStatusRefused, err.Error())
		q.logger.WarnContext(ctx, "AI analysis refused", slog.String("alert_id", job.alert.ID), slog.String("error", err.Error()))
	case err != nil:
		result = *q.state(domain.AIStatusFailed, err.Error())
		q.logger.WarnContext(ctx, "AI analysis failed", slog.String("alert_id", job.alert.ID), slog.String("error", err.Error()))
	default:
		result.Status = domain.AIStatusCompleted
		result.Provider, result.Model = q.analyzer.Provider(), q.analyzer.Model()
		q.logger.InfoContext(ctx, "AI analysis completed",
			slog.String("alert_id", job.alert.ID),
			slog.String("verdict", result.Verdict),
			slog.String("confidence", result.Confidence),
		)
	}
	now := time.Now().UTC()
	result.AnalyzedAt = &now

	q.store(ctx, job.alert, result)
	q.record(result.Status, time.Since(start))
}

func (q *AnalysisQueue) state(status, errMsg string) *domain.AIAnalysis {
	return &domain.AIAnalysis{Status: status, Provider: q.analyzer.Provider(), Model: q.analyzer.Model(), Error: errMsg}
}

func (q *AnalysisQueue) store(ctx context.Context, alert domain.Alert, analysis domain.AIAnalysis) {
	err := q.alerts.SetAIAnalysis(ctx, alert.IP, alert.ID, analysis)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		q.logger.DebugContext(ctx, "alert evicted before its analysis finished", slog.String("alert_id", alert.ID))
	case err != nil:
		q.logger.ErrorContext(ctx, "storing AI analysis failed", slog.String("alert_id", alert.ID), slog.String("error", err.Error()))
	}
}

func (q *AnalysisQueue) record(result string, d time.Duration) {
	if q.metrics != nil {
		q.metrics.RecordAIAnalysis(q.analyzer.Provider(), result, d)
	}
}
