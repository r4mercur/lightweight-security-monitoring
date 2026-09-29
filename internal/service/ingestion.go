package service

import (
	"context"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"log/slog"
	"time"
	"uuid"
)

// newID returns a version 7 UUID: IDs sort by creation time, which keeps them
// index-friendly for a future persistent store.
func newID() string { return uuid.NewV7().String() }

// maxClockSkew is how far an event timestamp may lie in the future.
const maxClockSkew = 5 * time.Minute

// AlertAnalysis schedules the AI analysis of new alerts (implemented by AnalysisQueue).
type AlertAnalysis interface {
	// Pending returns the analysis state to store with the alert, or nil if it is not analyzed.
	Pending(alert domain.Alert) *domain.AIAnalysis
	// Submit queues the stored alert for analysis without blocking.
	Submit(ctx context.Context, alert domain.Alert, event domain.Event)
}

// MetricsRecorder records ingestion-related metrics.
type MetricsRecorder interface {
	RecordEvent(eventType string)
	RecordAlert(severity string)
	RecordLatency(duration time.Duration)
}

// IngestionService orchestrates event ingestion, detection, AI analysis and persistence.
type IngestionService struct {
	events   repository.EventRepository
	alerts   repository.AlertRepository
	engine   *DetectionEngine
	analysis AlertAnalysis
	metrics  MetricsRecorder
	logger   *slog.Logger
}

// NewIngestionService creates a ready-to-use IngestionService. analysis may be
// nil to disable AI analysis.
func NewIngestionService(
	events repository.EventRepository,
	alerts repository.AlertRepository,
	engine *DetectionEngine,
	analysis AlertAnalysis,
	metrics MetricsRecorder,
	logger *slog.Logger,
) *IngestionService {
	return &IngestionService{
		events:   events,
		alerts:   alerts,
		engine:   engine,
		analysis: analysis,
		metrics:  metrics,
		logger:   logger,
	}
}

// Ingest processes an incoming event: persists it, runs detection and queues
// alerts for AI analysis.
func (s *IngestionService) Ingest(ctx context.Context, event domain.Event) (*domain.Alert, error) {
	start := time.Now()

	// Enrich event with server-side ID and timestamp if not provided.
	if event.ID == "" {
		event.ID = newID()
	}
	// All per-IP state keys on canonical values; callers usually normalize
	// already, this guards every source.
	if err := event.Normalize(); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	} else if event.Timestamp.After(now.Add(maxClockSkew)) {
		// A far-future timestamp would outlive retention and distort every
		// time window, so it is replaced with the receive time.
		s.logger.WarnContext(ctx, "event timestamp in the future, using receive time",
			slog.String("ip", event.IP),
			slog.Time("timestamp", event.Timestamp),
		)
		event.Timestamp = now
	}

	s.logger.InfoContext(ctx, "event received",
		slog.String("id", event.ID),
		slog.String("ip", event.IP),
		slog.String("type", string(event.EventType)),
	)

	// Persist the raw event.
	if err := s.events.SaveEvent(ctx, event); err != nil {
		return nil, fmt.Errorf("persisting event: %w", err)
	}
	s.metrics.RecordEvent(string(event.EventType))

	// Run detection rules against the enriched event.
	alert, triggered := s.engine.Evaluate(ctx, event, s.events, s.alerts)
	if !triggered {
		s.metrics.RecordLatency(time.Since(start))
		return nil, nil
	}

	// Enrich alert. The engine stamps alerts with the event time so that
	// cooldowns and correlation windows use the same clock as the rules.
	alert.ID = newID()

	// AI analysis runs in the background; the alert is stored as "pending" first.
	if s.analysis != nil {
		alert.AIAnalysis = s.analysis.Pending(*alert)
	}

	s.logger.WarnContext(ctx, "alert generated",
		slog.String("alert_id", alert.ID),
		slog.String("rule", alert.TriggerRule),
		slog.String("severity", string(alert.Severity)),
		slog.String("ip", alert.IP),
	)

	if err := s.alerts.SaveAlert(ctx, *alert); err != nil {
		return nil, fmt.Errorf("persisting alert: %w", err)
	}
	if alert.AIAnalysis != nil {
		s.analysis.Submit(ctx, *alert, event)
	}
	s.metrics.RecordAlert(string(alert.Severity))
	s.metrics.RecordLatency(time.Since(start))

	return alert, nil
}
