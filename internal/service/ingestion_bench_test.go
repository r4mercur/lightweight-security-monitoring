package service_test

import (
	"context"
	"fmt"
	"io"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/metrics"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"log/slog"
	"testing"
	"time"
)

// BenchmarkIngest_Flood measures the cost per event while one IP floods the
// service at 1000 req/s and the store already holds background traffic.
func BenchmarkIngest_Flood(b *testing.B) {
	ctx := context.Background()
	store := repository.NewMemoryStore()
	rules, err := service.DefaultRules()
	if err != nil {
		b.Fatal(err)
	}
	engine, err := service.NewDetectionEngine(rules)
	if err != nil {
		b.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingestion := service.NewIngestionService(store, store, engine, nil, metrics.NewMetrics(), logger)

	start := time.Now().UTC().Add(-time.Minute)
	for i := range 100_000 {
		_ = store.SaveEvent(ctx, domain.Event{
			IP:        fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255),
			EventType: domain.EventHTTPRequest,
			Path:      "/",
			Timestamp: start.Add(time.Duration(i) * time.Millisecond),
		})
	}

	b.ResetTimer()
	for i := range b.N {
		_, _ = ingestion.Ingest(ctx, domain.Event{
			IP:         "203.0.113.66",
			EventType:  domain.EventHTTPRequest,
			Path:       "/wp-content/x.php",
			StatusCode: 404,
			Timestamp:  start.Add(time.Duration(i) * time.Millisecond),
		})
	}
}
