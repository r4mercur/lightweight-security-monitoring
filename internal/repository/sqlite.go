package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"math"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure Go driver: no CGO, the binary stays static
)

// migrations are applied in order; PRAGMA user_version records how many have
// run. Append new steps, never edit released ones.
var migrations = []string{
	`
CREATE TABLE events (
	seq        INTEGER PRIMARY KEY, -- insertion order
	id         TEXT    NOT NULL,
	ip         TEXT    NOT NULL,
	ts         INTEGER NOT NULL,    -- event timestamp, Unix nanoseconds
	event_type TEXT    NOT NULL,
	data       TEXT    NOT NULL     -- the event as JSON
);
CREATE INDEX events_ip_ts ON events (ip, ts);
CREATE INDEX events_ts    ON events (ts);
CREATE INDEX events_type  ON events (event_type); -- with the implicit seq: newest of a type

CREATE TABLE alerts (
	seq          INTEGER PRIMARY KEY,
	id           TEXT    NOT NULL,
	ip           TEXT    NOT NULL,
	ts           INTEGER NOT NULL,
	severity     TEXT    NOT NULL,
	trigger_rule TEXT    NOT NULL,
	data         TEXT    NOT NULL
);
CREATE INDEX alerts_ip_ts ON alerts (ip, ts);
CREATE INDEX alerts_ts    ON alerts (ts);
CREATE INDEX alerts_id    ON alerts (id);
`,
}

const (
	// sqliteReaders is the number of parallel read connections. In WAL mode
	// readers never block the writer and vice versa.
	sqliteReaders = 4

	// Events are written in batches: a commit per event costs ~100 µs, an
	// insert within a batch ~10 µs. A batch is written when it is full, after
	// eventFlushDelay, and before events are read.
	eventBatchSize  = 1000
	eventFlushDelay = 100 * time.Millisecond
)

// SQLiteStore persists events and alerts in a SQLite database file. It
// implements both repositories with the same semantics as MemoryStore, except
// that capacity limits are enforced by Prune instead of on every insert.
//
// Events are buffered for up to eventFlushDelay before they are written; a
// crash (not a regular Close) loses them. Alerts are written immediately.
//
// Only one process may use the file: SQLite's locking does not work on
// network file systems (NFS, SMB, CephFS), so place it on a local disk or a
// block volume (Kubernetes: ReadWriteOnce).
type SQLiteStore struct {
	opts   options
	writer *sql.DB // one connection: SQLite allows a single writer at a time
	reader *sql.DB // read-only connections

	insertEvent, insertAlert *sql.Stmt

	bufMu   sync.Mutex // guards pending and timer
	pending []domain.Event
	timer   *time.Timer // flushes pending after eventFlushDelay; nil while pending is empty

	// writeMu orders event batches (so seq follows insertion order), alert
	// inserts and pruning, which recounts the tables.
	writeMu sync.Mutex

	// Sizes for Stats, so metrics scrapes don't scan the tables. Counts are
	// updated on insert and recounted by Prune; distinct IPs only by Prune.
	events, eventIPs, alerts atomic.Int64
}

// OpenSQLiteStore opens (or creates) the database at path and migrates its
// schema. Retention and capacity default to the same limits as MemoryStore.
func OpenSQLiteStore(ctx context.Context, path string, opts ...Option) (*SQLiteStore, error) {
	o := options{
		eventRetention: DefaultEventRetention,
		alertRetention: DefaultAlertRetention,
		maxEvents:      DefaultMaxEvents,
		maxAlerts:      DefaultMaxAlerts,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if path == "" || strings.Contains(path, "?") {
		return nil, fmt.Errorf("invalid database path %q", path)
	}

	s := &SQLiteStore{opts: o}
	var err error
	if s.writer, err = sql.Open("sqlite", sqliteDSN(path, false)); err != nil {
		return nil, err
	}
	s.writer.SetMaxOpenConns(1)
	s.writer.SetConnMaxIdleTime(0) // keep the connection: its prepared statements and page cache

	if err = s.init(ctx, path); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) init(ctx context.Context, path string) error {
	// The writer opens first: it creates the file and switches it to WAL mode.
	if err := migrate(ctx, s.writer); err != nil {
		return fmt.Errorf("opening database %s: %w", path, err)
	}
	var err error
	if s.reader, err = sql.Open("sqlite", sqliteDSN(path, true)); err != nil {
		return err
	}
	s.reader.SetMaxOpenConns(sqliteReaders)

	if s.insertEvent, err = s.writer.PrepareContext(ctx,
		`INSERT INTO events (id, ip, ts, event_type, data) VALUES (?, ?, ?, ?, ?)`); err != nil {
		return err
	}
	if s.insertAlert, err = s.writer.PrepareContext(ctx,
		`INSERT INTO alerts (id, ip, ts, severity, trigger_rule, data) VALUES (?, ?, ?, ?, ?, ?)`); err != nil {
		return err
	}
	return s.recount(ctx)
}

// sqliteDSN builds the connection string. WAL lets readers work while the
// writer commits; synchronous=NORMAL makes a commit a plain write (fsync only
// at checkpoints): a power loss may lose the last transactions, but never
// corrupts the database. busy_timeout covers other processes on the file,
// e.g. a backup tool such as Litestream.
func sqliteDSN(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Set("_txlock", "immediate") // take the write lock at BEGIN, not on the first write
	}
	// A plain path (no "file:" prefix): the driver strips the query, so
	// Windows paths need no URI escaping.
	return path + "?" + q.Encode()
}

func migrate(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("schema version %d is newer than this build supports (%d)", version, len(migrations))
	}
	for v := version; v < len(migrations); v++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close writes buffered events and releases the database. Call it after all
// writers have stopped.
func (s *SQLiteStore) Close() error {
	var errs []error
	if s.insertEvent != nil {
		errs = append(errs, s.flush(context.Background()))
	}
	for _, stmt := range []*sql.Stmt{s.insertEvent, s.insertAlert} {
		if stmt != nil {
			errs = append(errs, stmt.Close())
		}
	}
	if s.reader != nil {
		errs = append(errs, s.reader.Close())
	}
	if s.writer != nil {
		// Recommended before closing: refreshes query planner statistics where useful.
		_, err := s.writer.Exec("PRAGMA optimize")
		errs = append(errs, err, s.writer.Close())
	}
	return errors.Join(errs...)
}

// Prune removes events and alerts older than their retention and the oldest
// inserted items beyond capacity. Call it periodically.
func (s *SQLiteStore) Prune(now time.Time) error {
	ctx := context.Background()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var errs []error
	if err := s.flushLocked(ctx); err != nil {
		errs = append(errs, err)
	}
	del := func(kind, reason, query string, arg any) {
		res, err := s.writer.ExecContext(ctx, query, arg)
		if err != nil {
			errs = append(errs, fmt.Errorf("pruning %ss: %w", kind, err))
			return
		}
		n, _ := res.RowsAffected()
		s.evicted(kind, reason, int(n))
	}

	if s.opts.eventRetention > 0 {
		del("event", ReasonRetention, `DELETE FROM events WHERE ts < ?`, unixNano(now.Add(-s.opts.eventRetention)))
	}
	if s.opts.alertRetention > 0 {
		del("alert", ReasonRetention, `DELETE FROM alerts WHERE ts < ?`, unixNano(now.Add(-s.opts.alertRetention)))
	}
	// Keep the newest maxEvents rows (by insertion): delete everything up to
	// the first row beyond them.
	if s.opts.maxEvents > 0 {
		del("event", ReasonCapacity,
			`DELETE FROM events WHERE seq <= (SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?)`, s.opts.maxEvents)
	}
	if s.opts.maxAlerts > 0 {
		del("alert", ReasonCapacity,
			`DELETE FROM alerts WHERE seq <= (SELECT seq FROM alerts ORDER BY seq DESC LIMIT 1 OFFSET ?)`, s.opts.maxAlerts)
	}

	if err := s.recount(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// recount reads the table sizes. The caller holds writeMu (or no other
// goroutine uses the store yet), so the tables cannot change meanwhile;
// events still buffered are added to the count.
func (s *SQLiteStore) recount(ctx context.Context) error {
	var events, ips, alerts int64
	err := s.reader.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM events),
		(SELECT count(DISTINCT ip) FROM events),
		(SELECT count(*) FROM alerts)`).Scan(&events, &ips, &alerts)
	if err != nil {
		return fmt.Errorf("counting stored items: %w", err)
	}
	s.bufMu.Lock()
	s.events.Store(events + int64(len(s.pending)))
	s.bufMu.Unlock()
	s.eventIPs.Store(ips)
	s.alerts.Store(alerts)
	return nil
}

// Stats reports the number of stored items and distinct IPs. Distinct IPs are
// counted by Prune, so the value may lag up to one janitor interval.
func (s *SQLiteStore) Stats() Stats {
	return Stats{Events: int(s.events.Load()), EventIPs: int(s.eventIPs.Load()), Alerts: int(s.alerts.Load())}
}

func (s *SQLiteStore) evicted(kind, reason string, n int) {
	if n > 0 && s.opts.onEvict != nil {
		s.opts.onEvict(kind, reason, n)
	}
}

// ---- EventRepository ----

// SaveEvent buffers the event; it is written with the next batch. Only the
// caller that fills a batch writes it and receives a write error; errors of
// background writes go to the WithErrorFunc callback.
func (s *SQLiteStore) SaveEvent(ctx context.Context, event domain.Event) error {
	s.bufMu.Lock()
	s.pending = append(s.pending, event)
	s.events.Add(1)
	full := len(s.pending) >= eventBatchSize
	if !full && s.timer == nil {
		s.timer = time.AfterFunc(eventFlushDelay, s.flushInBackground)
	}
	s.bufMu.Unlock()

	if full {
		return s.flush(ctx)
	}
	return nil
}

func (s *SQLiteStore) flushInBackground() {
	if err := s.flush(context.Background()); err != nil && s.opts.onError != nil {
		s.opts.onError(err)
	}
}

// flush writes the buffered events in one transaction.
func (s *SQLiteStore) flush(ctx context.Context) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.flushLocked(ctx)
}

func (s *SQLiteStore) flushLocked(ctx context.Context) error {
	s.bufMu.Lock()
	batch := s.pending
	s.pending = nil
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.bufMu.Unlock()
	if len(batch) == 0 {
		return nil
	}

	// The batch holds other callers' events too: one canceled request must
	// not discard them.
	if err := s.writeEvents(context.WithoutCancel(ctx), batch); err != nil {
		s.events.Add(-int64(len(batch)))
		return fmt.Errorf("writing %d events: %w", len(batch), err)
	}
	return nil
}

func (s *SQLiteStore) writeEvents(ctx context.Context, batch []domain.Event) error {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	insert := tx.StmtContext(ctx, s.insertEvent)
	for _, event := range batch {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		// data as string: stored as TEXT, which SQLite's JSON functions expect.
		if _, err := insert.ExecContext(ctx,
			event.ID, event.IP, unixNano(event.Timestamp), string(event.EventType), string(data)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListEvents(ctx context.Context, q ListQuery) (ListResult[domain.Event], error) {
	if err := s.flush(ctx); err != nil {
		return ListResult[domain.Event]{}, err
	}
	var w where
	if q.EventType != "" {
		w.add("event_type = ?", string(q.EventType))
	}
	return listNewest[domain.Event](ctx, s.reader, "events", q, w)
}

// FindEventsByIPSince writes buffered events first, so the result includes
// every saved event. Rules that call it on every event therefore cost a
// commit per event.
func (s *SQLiteStore) FindEventsByIPSince(ctx context.Context, ip string, since time.Time) ([]domain.Event, error) {
	if err := s.flush(ctx); err != nil {
		return nil, err
	}
	return findSince[domain.Event](ctx, s.reader, "events", ip, since)
}

// ---- AlertRepository ----

// SaveAlert writes the alert immediately: cooldowns and correlation read it
// with the next event.
func (s *SQLiteStore) SaveAlert(ctx context.Context, alert domain.Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.insertAlert.ExecContext(ctx,
		alert.ID, alert.IP, unixNano(alert.Timestamp), string(alert.Severity), alert.TriggerRule, string(data)); err != nil {
		return err
	}
	s.alerts.Add(1)
	return nil
}

func (s *SQLiteStore) ListAlerts(ctx context.Context, q ListQuery) (ListResult[domain.Alert], error) {
	var w where
	if q.MinSeverity != "" {
		var sevs []string
		for _, sev := range []domain.Severity{domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical} {
			if sev.Rank() >= q.MinSeverity.Rank() {
				sevs = append(sevs, string(sev))
			}
		}
		w.in("severity", sevs)
	}
	if q.Rule != "" {
		w.add("trigger_rule = ?", q.Rule)
	}
	return listNewest[domain.Alert](ctx, s.reader, "alerts", q, w)
}

// SummarizeAlerts counts the alerts with a timestamp after since.
func (s *SQLiteStore) SummarizeAlerts(ctx context.Context, since time.Time) (AlertSummary, error) {
	sum := AlertSummary{BySeverity: map[domain.Severity]int{}}
	tx, err := s.reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true}) // one snapshot for all three counts
	if err != nil {
		return sum, err
	}
	defer func() { _ = tx.Rollback() }()

	group := func(column string) (map[string]int, error) {
		rows, err := tx.QueryContext(ctx,
			`SELECT `+column+`, count(*) FROM alerts WHERE ts > ? GROUP BY `+column, unixNano(since))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		counts := map[string]int{}
		for rows.Next() {
			var key string
			var n int
			if err := rows.Scan(&key, &n); err != nil {
				return nil, err
			}
			counts[key] = n
		}
		return counts, rows.Err()
	}

	bySeverity, err := group("severity")
	if err != nil {
		return sum, err
	}
	for sev, n := range bySeverity {
		sum.BySeverity[domain.Severity(sev)] = n
		sum.Total += n
	}
	ips, err := group("ip")
	if err != nil {
		return sum, err
	}
	rules, err := group("trigger_rule")
	if err != nil {
		return sum, err
	}
	sum.IPs = len(ips)
	sum.TopIPs, sum.TopRules = topCounts(ips, summaryTop), topCounts(rules, summaryTop)
	return sum, nil
}

func (s *SQLiteStore) FindAlertsByIPSince(ctx context.Context, ip string, since time.Time) ([]domain.Alert, error) {
	return findSince[domain.Alert](ctx, s.reader, "alerts", ip, since)
}

func (s *SQLiteStore) SetAIAnalysis(ctx context.Context, ip, alertID string, analysis domain.AIAnalysis) error {
	data, err := json.Marshal(analysis)
	if err != nil {
		return err
	}
	res, err := s.writer.ExecContext(ctx,
		`UPDATE alerts SET data = json_set(data, '$.ai_analysis', json(?)) WHERE ip = ? AND id = ?`,
		string(data), ip, alertID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Queries shared by events and alerts ----

// where collects the conditions of a query; values are always bound, never
// written into the SQL text.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, arg any) {
	w.conds = append(w.conds, cond)
	w.args = append(w.args, arg)
}

func (w *where) in(column string, values []string) {
	w.conds = append(w.conds, column+" IN ("+strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")+")")
	for _, v := range values {
		w.args = append(w.args, v)
	}
}

func (w where) String() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

// listNewest returns up to q.Limit items matching q.IP and w, newest first,
// and the number of matching items. Like MemoryStore: with an IP ordered by
// timestamp, without by insertion. Both queries run in one read transaction,
// so they see the same snapshot.
func listNewest[T any](ctx context.Context, db *sql.DB, table string, q ListQuery, w where) (res ListResult[T], err error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback() }()

	order := ` ORDER BY seq DESC`
	if q.IP != "" {
		w.add("ip = ?", q.IP)
		order = ` ORDER BY ts DESC, seq DESC`
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+table+w.String(), w.args...).Scan(&res.Total); err != nil {
		return res, err
	}
	res.Items, err = queryItems[T](ctx, tx,
		`SELECT data FROM `+table+w.String()+order+` LIMIT ?`, append(w.args, max(q.Limit, 0))...)
	return res, err
}

// findSince returns the items of ip with a timestamp after since, oldest first.
func findSince[T any](ctx context.Context, db *sql.DB, table, ip string, since time.Time) ([]T, error) {
	return queryItems[T](ctx, db,
		`SELECT data FROM `+table+` WHERE ip = ? AND ts > ? ORDER BY ts, seq`, ip, unixNano(since))
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func queryItems[T any](ctx context.Context, db querier, query string, args ...any) ([]T, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []T{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var item T
		if err := json.Unmarshal([]byte(data), &item); err != nil {
			return nil, fmt.Errorf("decoding stored item: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// unixNano converts t for the ts columns. UnixNano is undefined outside
// roughly 1678–2262, so such timestamps are clamped to keep their order.
func unixNano(t time.Time) int64 {
	switch {
	case t.Before(time.Unix(0, math.MinInt64)):
		return math.MinInt64
	case t.After(time.Unix(0, math.MaxInt64)):
		return math.MaxInt64
	}
	return t.UnixNano()
}
