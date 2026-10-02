package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Handler holds all dependencies needed by the HTTP handlers.
type Handler struct {
	ingestion *service.IngestionService
	events    repository.EventRepository
	alerts    repository.AlertRepository
	logger    *slog.Logger
}

// NewHandler creates a Handler with all required dependencies.
func NewHandler(
	ingestion *service.IngestionService,
	events repository.EventRepository,
	alerts repository.AlertRepository,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		ingestion: ingestion,
		events:    events,
		alerts:    alerts,
		logger:    logger,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /events  – ingest a new security event
// ─────────────────────────────────────────────────────────────────────────────

const (
	maxEventBytes = 64 << 10 // 64 KiB per single event request
	maxBatchBytes = 5 << 20  // 5 MiB per batch request
	// Events per batch request. Log shippers send whole buffer chunks (Fluent Bit:
	// up to ~2 MB, i.e. several thousand access log records); the byte limit
	// above is the actual bound.
	maxBatchSize = 10_000
)

func (h *Handler) IngestEvent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxEventBytes)

	var event domain.Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := validateEvent(&event); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	alert, err := h.ingestion.Ingest(ctx, event)
	if err != nil {
		h.logger.ErrorContext(ctx, "ingestion failed", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to process event")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if alert != nil {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "alert_generated",
			"alert":  alert,
		})
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /events/batch – ingest many events in one request
// Accepts a JSON array of events or newline-delimited JSON (one event per line).
// Invalid events are reported per index; the valid ones are still ingested.
// ─────────────────────────────────────────────────────────────────────────────

type batchError struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

type batchResponse struct {
	Received int             `json:"received"`
	Accepted int             `json:"accepted"`
	Alerts   []*domain.Alert `json:"alerts"`
	Errors   []batchError    `json:"errors"`
}

func (h *Handler) IngestBatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBatchBytes)

	raws, err := decodeBatch(r.Body)
	if err != nil {
		writeDecodeError(w, err)
		return
	}
	if len(raws) > maxBatchSize {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("batch exceeds %d events", maxBatchSize))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	resp := batchResponse{Received: len(raws), Alerts: []*domain.Alert{}, Errors: []batchError{}}
	for i, raw := range raws {
		if ctx.Err() != nil {
			resp.Errors = append(resp.Errors, batchError{Index: i, Error: "not processed: request deadline exceeded"})
			continue
		}

		var event domain.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			resp.Errors = append(resp.Errors, batchError{Index: i, Error: "invalid JSON: " + err.Error()})
			continue
		}
		if err := validateEvent(&event); err != nil {
			resp.Errors = append(resp.Errors, batchError{Index: i, Error: err.Error()})
			continue
		}

		alert, err := h.ingestion.Ingest(ctx, event)
		if err != nil {
			h.logger.ErrorContext(ctx, "batch ingestion failed", slog.Int("index", i), slog.String("error", err.Error()))
			resp.Errors = append(resp.Errors, batchError{Index: i, Error: "failed to process event"})
			continue
		}
		resp.Accepted++
		if alert != nil {
			resp.Alerts = append(resp.Alerts, alert)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// decodeBatch splits the body into raw events. A body starting with '[' is
// read as a JSON array, anything else as a stream of JSON objects (NDJSON).
func decodeBatch(body io.Reader) ([]json.RawMessage, error) {
	br := bufio.NewReader(body)
	first, err := peekNonSpace(br)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty batch")
		}
		return nil, err
	}

	dec := json.NewDecoder(br)
	var raws []json.RawMessage
	if first == '[' {
		if err := dec.Decode(&raws); err != nil {
			return nil, err
		}
		return raws, nil
	}
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return raws, nil
			}
			return nil, err
		}
		raws = append(raws, raw)
		if len(raws) > maxBatchSize {
			return raws, nil // caller rejects the batch; no need to read further
		}
	}
}

func peekNonSpace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return b, br.UnreadByte()
		}
	}
}

// validateEvent checks required fields and fills defaults.
func validateEvent(event *domain.Event) error {
	return event.Normalize()
}

func writeDecodeError(w http.ResponseWriter, err error) {
	if tooLarge, ok := errors.AsType[*http.MaxBytesError](err); ok {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", tooLarge.Limit))
		return
	}
	writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /events?ip=&type=&limit= – newest stored events
// ─────────────────────────────────────────────────────────────────────────────

const (
	defaultListLimit = 100
	maxListLimit     = 1000
)

func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	q, err := parseListQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := h.events.ListEvents(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not retrieve events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(res.Items),
		"total":  res.Total,
		"events": nonNil(res.Items),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /alerts?ip=&severity=&rule=&limit= – newest generated alerts
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	q, err := parseListQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := h.alerts.ListAlerts(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not retrieve alerts")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(res.Items),
		"total":  res.Total,
		"alerts": nonNil(res.Items),
	})
}

func parseListQuery(r *http.Request) (repository.ListQuery, error) {
	q := repository.ListQuery{Limit: defaultListLimit}
	if ip := r.URL.Query().Get("ip"); ip != "" {
		normalized, err := domain.NormalizeIP(ip)
		if err != nil {
			return q, fmt.Errorf("parameter 'ip' is not a valid IP address: %q", ip)
		}
		q.IP = normalized
	}
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxListLimit {
			return q, fmt.Errorf("parameter 'limit' must be between 1 and %d", maxListLimit)
		}
		q.Limit = n
	}
	q.EventType = domain.EventType(r.URL.Query().Get("type"))
	if s := r.URL.Query().Get("severity"); s != "" {
		q.MinSeverity = domain.Severity(strings.ToLower(s))
		if !q.MinSeverity.Valid() {
			return q, fmt.Errorf("parameter 'severity' must be low, medium, high or critical, got %q", s)
		}
	}
	q.Rule = r.URL.Query().Get("rule")
	return q, nil
}

// nonNil makes empty results encode as [] instead of null.
func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /health – liveness probe
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
