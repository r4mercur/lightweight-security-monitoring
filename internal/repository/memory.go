package repository

import (
	"context"
	"errors"
	"lightweight-security-monitoring/internal/domain"
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

// ListQuery selects the newest items, optionally for a single IP.
type ListQuery struct {
	IP    string
	Limit int
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

// Prune removes events and alerts older than their retention. Call it periodically.
func (m *MemoryStore) Prune(now time.Time) {
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
}

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
	items, total := m.events.newest(q.IP, q.Limit)
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
	items, total := m.alerts.newest(q.IP, q.Limit)
	return ListResult[domain.Alert]{Items: items, Total: total}, nil
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
