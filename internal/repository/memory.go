package repository

import (
	"context"
	"errors"
	"lightweight-security-monitoring/internal/domain"
	"slices"
	"strings"
	"sync"
	"time"
)

// EventRepository defines the contract for event persistence.
type EventRepository interface {
	SaveEvent(ctx context.Context, event domain.Event) error
	ListEvents(ctx context.Context, q ListQuery) (ListResult[domain.Event], error)
	FindEventsByIPSince(ctx context.Context, ip string, since time.Time) ([]domain.Event, error)
}

// AlertRepository defines the contract for alert persistence.
type AlertRepository interface {
	SaveAlert(ctx context.Context, alert domain.Alert) error
	ListAlerts(ctx context.Context, q ListQuery) (ListResult[domain.Alert], error)
	FindAlertsByIPSince(ctx context.Context, ip string, since time.Time) ([]domain.Alert, error)
	// SetAIAnalysis attaches an AI analysis to a stored alert. It returns
	// ErrNotFound when the alert no longer exists (e.g. evicted meanwhile).
	SetAIAnalysis(ctx context.Context, ip, alertID string, analysis domain.AIAnalysis) error
}

// ErrNotFound is returned when a requested item does not exist.
var ErrNotFound = errors.New("not found")

// ListQuery selects the newest items, optionally for a single IP and filtered.
type ListQuery struct {
	IP    string
	Limit int

	EventType   domain.EventType // events only: exact event type
	MinSeverity domain.Severity  // alerts only: at least this severity
	Rule        string           // alerts only: trigger rule
}

func (q ListQuery) eventFilter() func(domain.Event) bool {
	if q.EventType == "" {
		return nil
	}
	return func(e domain.Event) bool { return e.EventType == q.EventType }
}

func (q ListQuery) alertFilter() func(domain.Alert) bool {
	if q.MinSeverity == "" && q.Rule == "" {
		return nil
	}
	return func(a domain.Alert) bool {
		return a.Severity.Rank() >= q.MinSeverity.Rank() && (q.Rule == "" || a.TriggerRule == q.Rule)
	}
}

// AlertSummary counts the alerts since a point in time.
type AlertSummary struct {
	Total      int
	IPs        int // distinct source IPs
	BySeverity map[domain.Severity]int
	TopIPs     []Count // most alerts first, at most summaryTop
	TopRules   []Count // by trigger rule
}

// Count is a key with its number of items.
type Count struct {
	Key   string
	Count int
}

// summaryTop is the length of the top lists in an AlertSummary.
const summaryTop = 10

// topCounts sorts counts by count (descending), then key, and keeps the first n.
func topCounts(counts map[string]int, n int) []Count {
	out := make([]Count, 0, len(counts))
	for k, c := range counts {
		out = append(out, Count{Key: k, Count: c})
	}
	slices.SortFunc(out, func(a, b Count) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out[:min(n, len(out))]
}

// ListResult is a page of items (newest first) and the number of stored items matching the query.
type ListResult[T any] struct {
	Items []T
	Total int
}

// ─────────────────────────────────────────────────────────────────────────────
// Options
// ─────────────────────────────────────────────────────────────────────────────

// Defaults keep memory bounded (roughly 1 KiB per stored event).
const (
	DefaultEventRetention = 24 * time.Hour
	DefaultAlertRetention = 7 * 24 * time.Hour
	DefaultMaxEvents      = 200_000
	DefaultMaxAlerts      = 50_000
)

// Eviction reasons reported to the EvictionFunc.
const (
	ReasonRetention = "retention"
	ReasonCapacity  = "capacity"
)

// EvictionFunc is called when items are dropped; kind is "event" or "alert".
type EvictionFunc func(kind, reason string, n int)

type options struct {
	eventRetention time.Duration
	alertRetention time.Duration
	maxEvents      int
	maxAlerts      int
	onEvict        EvictionFunc
	onError        func(error)
}

// Option configures a MemoryStore.
type Option func(*options)

// WithRetention sets how long events and alerts are kept, measured from their timestamp. 0 keeps them forever.
func WithRetention(events, alerts time.Duration) Option {
	return func(o *options) { o.eventRetention, o.alertRetention = events, alerts }
}

// WithCapacity caps the number of stored events and alerts; the oldest inserted are evicted first. 0 means unlimited.
func WithCapacity(maxEvents, maxAlerts int) Option {
	return func(o *options) { o.maxEvents, o.maxAlerts = maxEvents, maxAlerts }
}

// WithEvictionFunc registers a callback for dropped items, e.g. for metrics.
func WithEvictionFunc(f EvictionFunc) Option {
	return func(o *options) { o.onEvict = f }
}

// WithErrorFunc registers a callback for errors that no caller receives, such
// as a failed background write of buffered events (SQLiteStore only).
func WithErrorFunc(f func(error)) Option {
	return func(o *options) { o.onError = f }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryStore
// ─────────────────────────────────────────────────────────────────────────────

// MemoryStore is a thread-safe in-memory implementation of both repositories.
// Items are indexed by IP and bounded by retention and capacity.
type MemoryStore struct {
	mu     sync.RWMutex
	opts   options
	events *indexedLog[domain.Event]
	alerts *indexedLog[domain.Alert]
}

// NewMemoryStore creates a new MemoryStore with the default limits unless overridden.
func NewMemoryStore(opts ...Option) *MemoryStore {
	o := options{
		eventRetention: DefaultEventRetention,
		alertRetention: DefaultAlertRetention,
		maxEvents:      DefaultMaxEvents,
		maxAlerts:      DefaultMaxAlerts,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return &MemoryStore{
		opts:   o,
		events: newIndexedLog[domain.Event](o.maxEvents),
		alerts: newIndexedLog[domain.Alert](o.maxAlerts),
	}
}

// Prune removes events and alerts older than their retention. Call it
// periodically. It never fails; the error matches SQLiteStore.Prune.
func (m *MemoryStore) Prune(now time.Time) error {
	m.mu.Lock()
	var events, alerts int
	if m.opts.eventRetention > 0 {
		events = m.events.pruneBefore(now.Add(-m.opts.eventRetention))
	}
	if m.opts.alertRetention > 0 {
		alerts = m.alerts.pruneBefore(now.Add(-m.opts.alertRetention))
	}
	m.mu.Unlock()

	m.evicted("event", ReasonRetention, events)
	m.evicted("alert", ReasonRetention, alerts)
	return nil
}

// Close does nothing: stored items are lost when the process exits.
func (m *MemoryStore) Close() error { return nil }

// Stats reports the number of stored items and distinct IPs.
type Stats struct {
	Events, EventIPs, Alerts int
}

func (m *MemoryStore) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Stats{Events: m.events.len(), EventIPs: m.events.keys(), Alerts: m.alerts.len()}
}

func (m *MemoryStore) evicted(kind, reason string, n int) {
	if n > 0 && m.opts.onEvict != nil {
		m.opts.onEvict(kind, reason, n)
	}
}

// ---- EventRepository ----

func (m *MemoryStore) SaveEvent(_ context.Context, event domain.Event) error {
	m.mu.Lock()
	n := m.events.add(event.IP, event.Timestamp, event)
	m.mu.Unlock()
	m.evicted("event", ReasonCapacity, n)
	return nil
}

func (m *MemoryStore) ListEvents(_ context.Context, q ListQuery) (ListResult[domain.Event], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items, total := m.events.newest(q.IP, q.Limit, q.eventFilter())
	return ListResult[domain.Event]{Items: items, Total: total}, nil
}

func (m *MemoryStore) FindEventsByIPSince(_ context.Context, ip string, since time.Time) ([]domain.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.events.since(ip, since), nil
}

// ---- AlertRepository ----

func (m *MemoryStore) SaveAlert(_ context.Context, alert domain.Alert) error {
	m.mu.Lock()
	n := m.alerts.add(alert.IP, alert.Timestamp, alert)
	m.mu.Unlock()
	m.evicted("alert", ReasonCapacity, n)
	return nil
}

func (m *MemoryStore) ListAlerts(_ context.Context, q ListQuery) (ListResult[domain.Alert], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items, total := m.alerts.newest(q.IP, q.Limit, q.alertFilter())
	return ListResult[domain.Alert]{Items: items, Total: total}, nil
}

// SummarizeAlerts counts the alerts with a timestamp after since.
func (m *MemoryStore) SummarizeAlerts(_ context.Context, since time.Time) (AlertSummary, error) {
	sum := AlertSummary{BySeverity: map[domain.Severity]int{}}
	ips, rules := map[string]int{}, map[string]int{}
	m.mu.RLock()
	m.alerts.eachSince(since, func(a domain.Alert) {
		sum.Total++
		sum.BySeverity[a.Severity]++
		ips[a.IP]++
		rules[a.TriggerRule]++
	})
	m.mu.RUnlock()
	sum.IPs = len(ips)
	sum.TopIPs, sum.TopRules = topCounts(ips, summaryTop), topCounts(rules, summaryTop)
	return sum, nil
}

func (m *MemoryStore) FindAlertsByIPSince(_ context.Context, ip string, since time.Time) ([]domain.Alert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.alerts.since(ip, since), nil
}

// SetAIAnalysis replaces the alert's analysis. The analysis is stored as a new
// value, never modified in place, so alerts handed out earlier stay consistent.
func (m *MemoryStore) SetAIAnalysis(_ context.Context, ip, alertID string, analysis domain.AIAnalysis) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := m.alerts.update(ip, func(a *domain.Alert) bool {
		if a.ID != alertID {
			return false
		}
		a.AIAnalysis = &analysis
		return true
	})
	if !found {
		return ErrNotFound
	}
	return nil
}
