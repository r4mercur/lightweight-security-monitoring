package web_test

import (
	"bytes"
	"context"
	"io"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/metrics"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"lightweight-security-monitoring/internal/web"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	user     = "admin"
	password = "correct horse battery staple"
)

// newUI returns the UI over a store filled through the real ingestion
// pipeline. Logged errors (e.g. a template that fails half-way) fail the test.
func newUI(t *testing.T, events ...domain.Event) (http.Handler, *repository.MemoryStore) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError}))
	t.Cleanup(func() {
		if logs.Len() > 0 {
			t.Errorf("errors logged:\n%s", logs.String())
		}
	})

	rules, err := service.DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := service.NewDetectionEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	store := repository.NewMemoryStore()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingestion := service.NewIngestionService(store, store, engine, nil, metrics.NewMetrics(), quiet)
	for _, e := range events {
		if _, err := ingestion.Ingest(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}

	h, err := web.New(web.Config{User: user, Password: password, Store: store, Rules: rules.Specs, Logger: logger, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	return h, store
}

func get(t *testing.T, h http.Handler, path string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.SetBasicAuth(user, password)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBasicAuth(t *testing.T) {
	h, _ := newUI(t)
	cases := []struct {
		name           string
		user, password string
		noAuth         bool
		want           int
	}{
		{name: "no credentials", noAuth: true, want: http.StatusUnauthorized},
		{name: "wrong password", user: user, password: "wrong", want: http.StatusUnauthorized},
		{name: "wrong user", user: "root", password: password, want: http.StatusUnauthorized},
		{name: "correct", user: user, password: password, want: http.StatusOK},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		if !c.noAuth {
			req.SetBasicAuth(c.user, c.password)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.want)
		}
		if c.want == http.StatusUnauthorized && !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
			t.Errorf("%s: missing Basic challenge", c.name)
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
			t.Errorf("%s: missing CSP", c.name)
		}
	}
}

func TestNewRequiresPassword(t *testing.T) {
	if _, err := web.New(web.Config{User: user, Store: repository.NewMemoryStore(), Logger: slog.Default()}); err == nil {
		t.Error("expected an error without password")
	}
}

// Attackers write paths, user agents and DNS names; the UI must show them as text.
func TestAttackerInputIsEscaped(t *testing.T) {
	h, _ := newUI(t,
		domain.Event{IP: "203.0.113.9", EventType: domain.EventHTTPRequest,
			Path:      `/search?q=<script>alert(1)</script>`,
			UserAgent: `"><img src=x onerror=alert(2)>`,
			Metadata:  map[string]string{"x": `<svg onload=alert(3)>`},
		},
		domain.Event{IP: "203.0.113.9", EventType: domain.EventHTTPRequest, Path: `/a" hx-get="/ui/rules" hx-trigger="load`},
	)

	for _, path := range []string{"/ui/", "/ui/alerts", "/ui/events", "/ui/ips/203.0.113.9"} {
		body := get(t, h, path).Body.String()
		for _, raw := range []string{"<script>alert", "<img src=x", "<svg onload", `" hx-get="/ui/rules`} {
			if strings.Contains(body, raw) {
				t.Errorf("%s: unescaped attacker input %q in page", path, raw)
			}
		}
		if !strings.Contains(body, "&lt;script") {
			t.Errorf("%s: escaped payload not shown", path)
		}
	}
}

func TestPagesRender(t *testing.T) {
	h, _ := newUI(t,
		domain.Event{IP: "10.0.0.1", EventType: domain.EventHTTPRequest, Path: "/.env"},
		domain.Event{IP: "2001:db8::7", EventType: domain.EventDNSQuery, Domain: "example.com"},
		domain.Event{IP: "10.0.0.2", EventType: domain.EventFirewallBlock, DstIP: "192.0.2.1", Port: 22, Protocol: "tcp", Direction: "inbound"},
	)
	for path, want := range map[string]string{
		"/ui/":                  "Top source IPs",
		"/ui/alerts":            "SensitivePath",
		"/ui/events":            "192.0.2.1:22",
		"/ui/ips/2001:db8::7":   "example.com",
		"/ui/ips/2001:DB8:0::7": "example.com", // any spelling of the address
		"/ui/rules":             "BruteForce",
	} {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: status %d, want body containing %q", path, rec.Code, want)
		}
		if !strings.Contains(rec.Body.String(), "<!doctype html>") || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: not a full, uncached page", path)
		}
	}
}

func TestHtmxRequestGetsOnlyResults(t *testing.T) {
	h, _ := newUI(t, domain.Event{IP: "10.0.0.1", EventType: domain.EventHTTPRequest, Path: "/.env"})

	rec := get(t, h, "/ui/alerts?severity=medium", "HX-Request", "true", "HX-Target", "results")
	body := strings.TrimSpace(rec.Body.String())
	if !strings.HasPrefix(body, `<div id="results">`) || strings.Contains(body, "<html") {
		t.Errorf("partial response expected, got:\n%s", body)
	}

	// Going back in history with an empty htmx cache needs the whole page.
	rec = get(t, h, "/ui/alerts", "HX-Request", "true", "HX-Target", "results", "HX-History-Restore-Request", "true")
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Error("history restore must get the full page")
	}
}

func TestAlertFilters(t *testing.T) {
	h, _ := newUI(t,
		domain.Event{IP: "10.0.0.1", EventType: domain.EventHTTPRequest, Path: "/.env"},         // SensitivePath, medium
		domain.Event{IP: "10.0.0.2", EventType: domain.EventHTTPRequest, Path: "/?q=1' OR 1=1"}, // SQLInjection, high
	)
	count := regexp.MustCompile(`(\d+) of (\d+) alerts`)
	for query, want := range map[string]string{
		"":                       "2 of 2",
		"?severity=high":         "1 of 1",
		"?rule=SensitivePath":    "1 of 1",
		"?ip=10.0.0.2":           "1 of 1",
		"?ip=10.0.0.9":           "0 of 0",
		"?severity=bogus":        "2 of 2", // invalid filters are reported and ignored
		"?ip=not-an-ip&limit=50": "2 of 2",
	} {
		body := get(t, h, "/ui/alerts"+query).Body.String()
		m := count.FindStringSubmatch(body)
		if m == nil || m[1]+" of "+m[2] != want {
			t.Errorf("%q: got %v, want %q", query, m, want)
		}
	}
	if body := get(t, h, "/ui/alerts?ip=not-an-ip").Body.String(); !strings.Contains(body, "is not a valid IP address") {
		t.Error("invalid IP not reported")
	}
}

func TestPollAlerts(t *testing.T) {
	h, store := newUI(t, domain.Event{IP: "10.0.0.1", EventType: domain.EventHTTPRequest, Path: "/.env"})
	res, _ := store.ListAlerts(context.Background(), repository.ListQuery{Limit: 1})
	newest := res.Items[0].ID

	if rec := get(t, h, "/ui/alerts/poll?newest="+newest); rec.Code != http.StatusNoContent {
		t.Errorf("no new alert: status %d, want 204", rec.Code)
	}
	rec := get(t, h, "/ui/alerts/poll?newest=older-id&severity=low")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `href="/ui/alerts?severity=low"`) {
		t.Errorf("new alert: status %d, body %s", rec.Code, rec.Body)
	}
	// A filter the new alert does not match: nothing to show.
	if rec := get(t, h, "/ui/alerts/poll?newest=older-id&severity=critical"); rec.Code != http.StatusNoContent {
		t.Errorf("filtered: status %d, want 204", rec.Code)
	}
}

func TestIPPageRejectsInvalidAddress(t *testing.T) {
	h, _ := newUI(t)
	if rec := get(t, h, "/ui/ips/not-an-ip"); rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", rec.Code)
	}
}

func TestStaticFiles(t *testing.T) {
	h, _ := newUI(t)
	// Pages reference the files with a content hash, so a long cache time is safe.
	page := get(t, h, "/ui/rules").Body.String()
	for _, ref := range []*regexp.Regexp{
		regexp.MustCompile(`href="/ui/static/app\.css\?v=[0-9a-f]{12}"`),
		regexp.MustCompile(`src="/ui/static/htmx\.min\.js\?v=[0-9a-f]{12}"`),
		regexp.MustCompile(`src="/ui/static/table\.js\?v=[0-9a-f]{12}"`),
		regexp.MustCompile(`<link rel="icon" type="image/svg\+xml" href="/ui/static/logo\.svg\?v=[0-9a-f]{12}">`),
		regexp.MustCompile(`<img src="/ui/static/logo\.svg\?v=[0-9a-f]{12}"`),
	} {
		if !ref.MatchString(page) {
			t.Errorf("page does not reference %s", ref)
		}
	}

	for path, contentType := range map[string]string{
		"/ui/static/htmx.min.js": "text/javascript",
		"/ui/static/app.css":     "text/css",
		"/ui/static/table.js":    "text/javascript",
		"/ui/static/logo.svg":    "image/svg+xml",
	} {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), contentType) {
			t.Errorf("%s: status %d, content type %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}
