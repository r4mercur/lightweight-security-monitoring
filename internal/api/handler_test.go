package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"lightweight-security-monitoring/internal/api"
	"lightweight-security-monitoring/internal/metrics"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newServer(t *testing.T, apiKeys ...string) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rules, err := service.DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := service.NewDetectionEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	store := repository.NewMemoryStore()
	m := metrics.NewMetrics()
	ingestion := service.NewIngestionService(store, store, engine, nil, m, logger)
	handler := api.NewHandler(ingestion, store, store, logger)
	return api.SetupRoutes(handler, m, api.NewAPIKeyAuth(apiKeys))
}

func do(t *testing.T, srv http.Handler, method, path, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func TestAuth(t *testing.T) {
	srv := newServer(t, "secret-1", " secret-2 ")
	event := `{"ip":"10.0.0.1","event_type":"http_request","path":"/"}`

	cases := []struct {
		name    string
		headers []string
		want    int
	}{
		{"no key", nil, http.StatusUnauthorized},
		{"wrong key", []string{"Authorization", "Bearer nope"}, http.StatusUnauthorized},
		{"bearer", []string{"Authorization", "Bearer secret-1"}, http.StatusAccepted},
		{"x-api-key, second key trimmed", []string{"X-API-Key", "secret-2"}, http.StatusAccepted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := do(t, srv, "POST", "/events", event, tc.headers...); rec.Code != tc.want {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body)
			}
		})
	}

	if rec := do(t, srv, "GET", "/alerts", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /alerts without key: status = %d, want 401", rec.Code)
	}
	if rec := do(t, srv, "GET", "/health", ""); rec.Code != http.StatusOK {
		t.Errorf("/health must stay open, got %d", rec.Code)
	}
}

func TestAuth_DisabledWithoutKeys(t *testing.T) {
	srv := newServer(t, "", "  ")
	if rec := do(t, srv, "GET", "/events", ""); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when no keys are configured", rec.Code)
	}
}

// ── Single event validation ───────────────────────────────────────────────────

func TestIngestEvent_Validation(t *testing.T) {
	srv := newServer(t)
	cases := map[string]struct {
		body string
		want int
	}{
		"missing ip":   {`{"event_type":"http_request"}`, http.StatusBadRequest},
		"invalid ip":   {`{"ip":"not-an-ip"}`, http.StatusBadRequest},
		"ipv6":         {`{"ip":"2001:db8::1"}`, http.StatusAccepted},
		"too large":    {`{"ip":"10.0.0.1","message":"` + strings.Repeat("a", 70<<10) + `"}`, http.StatusRequestEntityTooLarge},
		"invalid json": {`{"ip":`, http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := do(t, srv, "POST", "/events", tc.body); rec.Code != tc.want {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

// ── Batch ─────────────────────────────────────────────────────────────────────

type batchResponse struct {
	Received int `json:"received"`
	Accepted int `json:"accepted"`
	Alerts   []struct {
		TriggerRule string `json:"trigger_rule"`
	} `json:"alerts"`
	Errors []struct {
		Index int    `json:"index"`
		Error string `json:"error"`
	} `json:"errors"`
}

func decodeBatch(t *testing.T, rec *httptest.ResponseRecorder) batchResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body)
	}
	var resp batchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestIngestBatch_JSONArray(t *testing.T) {
	srv := newServer(t)
	body := `[
		{"ip":"10.0.0.1","event_type":"http_request","path":"/"},
		{"ip":"10.0.0.2","event_type":"http_request","path":"/.env"},
		{"event_type":"http_request"},
		{"ip":"10.0.0.3","port":"not a number"}
	]`
	resp := decodeBatch(t, do(t, srv, "POST", "/events/batch", body))

	if resp.Received != 4 || resp.Accepted != 2 {
		t.Errorf("received/accepted = %d/%d, want 4/2", resp.Received, resp.Accepted)
	}
	if len(resp.Alerts) != 1 || resp.Alerts[0].TriggerRule != "SensitivePath" {
		t.Errorf("expected one SensitivePath alert, got %+v", resp.Alerts)
	}
	if len(resp.Errors) != 2 || resp.Errors[0].Index != 2 || resp.Errors[1].Index != 3 {
		t.Errorf("expected errors for index 2 and 3, got %+v", resp.Errors)
	}
}

func TestIngestBatch_NDJSON(t *testing.T) {
	srv := newServer(t)
	var lines []string
	for range 5 {
		lines = append(lines, `{"ip":"10.0.0.9","event_type":"failed_login"}`)
	}
	// 5 prior failed logins are needed, so the 6th event triggers BruteForce.
	lines = append(lines, `{"ip":"10.0.0.9","event_type":"failed_login"}`)

	resp := decodeBatch(t, do(t, srv, "POST", "/events/batch", strings.Join(lines, "\n")+"\n"))
	if resp.Accepted != 6 {
		t.Errorf("accepted = %d, want 6", resp.Accepted)
	}
	if len(resp.Alerts) != 1 || resp.Alerts[0].TriggerRule != "BruteForce" {
		t.Errorf("expected exactly one BruteForce alert (cooldown), got %+v", resp.Alerts)
	}
}

func TestIngestBatch_Rejections(t *testing.T) {
	srv := newServer(t)
	tooMany := "[" + strings.TrimSuffix(strings.Repeat(`{"ip":"10.0.0.1"},`, 10_001), ",") + "]"

	cases := map[string]struct {
		body string
		want int
	}{
		"empty":         {"  \n", http.StatusBadRequest},
		"broken json":   {`[{"ip":"10.0.0.1"`, http.StatusBadRequest},
		"broken ndjson": {"{\"ip\":\"10.0.0.1\"}\n{oops}", http.StatusBadRequest},
		"too many":      {tooMany, http.StatusRequestEntityTooLarge},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := do(t, srv, "POST", "/events/batch", tc.body); rec.Code != tc.want {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

// ── Listing ───────────────────────────────────────────────────────────────────

func TestListEvents_LimitAndIPFilter(t *testing.T) {
	srv := newServer(t)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.1", "2001:db8::1"} {
		do(t, srv, "POST", "/events", `{"ip":"`+ip+`","event_type":"http_request","path":"/"}`)
	}

	var resp struct {
		Count  int `json:"count"`
		Total  int `json:"total"`
		Events []struct {
			IP string `json:"ip"`
		} `json:"events"`
	}
	decode := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body)
		}
		resp.Events = nil
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
	}

	decode(do(t, srv, "GET", "/events?limit=2", ""))
	if resp.Count != 2 || resp.Total != 4 || resp.Events[0].IP != "2001:db8::1" {
		t.Errorf("limit=2: got %+v", resp)
	}

	decode(do(t, srv, "GET", "/events?ip=10.0.0.1", ""))
	if resp.Count != 2 || resp.Total != 2 {
		t.Errorf("ip filter: got %+v", resp)
	}

	// Filtering normalizes the address like ingestion does.
	decode(do(t, srv, "GET", "/events?ip=2001:0DB8::1", ""))
	if resp.Total != 1 {
		t.Errorf("ip filter with different spelling: got %+v", resp)
	}

	if !strings.Contains(do(t, srv, "GET", "/alerts", "").Body.String(), `"alerts":[]`) {
		t.Error("empty alert list must encode as [] instead of null")
	}
}

func TestListEvents_InvalidParameters(t *testing.T) {
	srv := newServer(t)
	for _, query := range []string{"limit=0", "limit=1001", "limit=abc", "ip=nope", "severity=urgent"} {
		if rec := do(t, srv, "GET", "/events?"+query, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", query, rec.Code)
		}
	}
}

func TestList_TypeSeverityAndRuleFilters(t *testing.T) {
	srv := newServer(t)
	do(t, srv, "POST", "/events", `{"ip":"10.0.0.1","event_type":"http_request","path":"/.env"}`)         // SensitivePath, medium
	do(t, srv, "POST", "/events", `{"ip":"10.0.0.2","event_type":"http_request","path":"/?q=1' OR 1=1"}`) // SQLInjection, high
	do(t, srv, "POST", "/events", `{"ip":"10.0.0.3","event_type":"dns_query","domain":"example.com"}`)

	total := func(path string) string {
		var resp struct {
			Total int `json:"total"`
		}
		rec := do(t, srv, "GET", path, "")
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return fmt.Sprintf("%d %d", rec.Code, resp.Total)
	}
	for path, want := range map[string]string{
		"/events?type=dns_query":                   "200 1",
		"/events?type=http_request":                "200 2",
		"/alerts?severity=medium":                  "200 2",
		"/alerts?severity=HIGH":                    "200 1",
		"/alerts?rule=SensitivePath":               "200 1",
		"/alerts?severity=high&rule=SensitivePath": "200 0",
	} {
		if got := total(path); got != want {
			t.Errorf("%s: got %q, want %q", path, got, want)
		}
	}
}

func TestIngestEvent_NetworkFields(t *testing.T) {
	srv := newServer(t)
	ok := `{"ip":"203.0.113.5","event_type":"firewall_block","dst_ip":"192.0.2.10","port":22,"src_port":50000,"protocol":"TCP","direction":"inbound"}`
	if rec := do(t, srv, "POST", "/events", ok); rec.Code != http.StatusAccepted {
		t.Errorf("valid network event: status = %d (%s)", rec.Code, rec.Body)
	}
	bad := `{"ip":"203.0.113.5","dst_ip":"x","port":99999,"direction":"up"}`
	rec := do(t, srv, "POST", "/events", bad)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "dst_ip") || !strings.Contains(rec.Body.String(), "direction") {
		t.Errorf("invalid network event: status = %d (%s)", rec.Code, rec.Body)
	}
}
