package api

import (
	"lightweight-security-monitoring/internal/metrics"
	"net/http"
)

// SetupRoutes wires all HTTP routes and returns the mux.
// Event and alert endpoints require an API key when auth is enabled;
// /health and /metrics stay open for probes and scrapers.
func SetupRoutes(h *Handler, m *metrics.Metrics, auth *APIKeyAuth) http.Handler {
	mux := http.NewServeMux()

	// Event ingestion & query
	mux.HandleFunc("POST /events", auth.Require(h.IngestEvent))
	mux.HandleFunc("POST /events/batch", auth.Require(h.IngestBatch))
	mux.HandleFunc("GET /events", auth.Require(h.ListEvents))

	// Alerts
	mux.HandleFunc("GET /alerts", auth.Require(h.ListAlerts))

	// Observability
	mux.HandleFunc("GET /health", h.HealthCheck)
	mux.Handle("GET /metrics", m.Handler())

	return mux
}
