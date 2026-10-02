package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTestDB(t testing.TB, opts ...Option) (*SQLiteStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "monitoring.db")
	s, err := OpenSQLiteStore(context.Background(), path, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func saveAll(t *testing.T, s *SQLiteStore, events ...domain.Event) {
	t.Helper()
	for _, e := range events {
		if err := s.SaveEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLite_FindEventsByIPSince_SortsByTime(t *testing.T) {
	s, _ := openTestDB(t)
	saveAll(t, s,
		ev("a1", "10.0.0.1", 0),
		ev("b1", "10.0.0.2", time.Second),
		ev("a3", "10.0.0.1", 3*time.Second),
		ev("a2", "10.0.0.1", 2*time.Second), // out of order
	)

	got, err := s.FindEventsByIPSince(context.Background(), "10.0.0.1", t0)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a2", "a3"}; !slices.Equal(ids(got), want) {
		t.Errorf("got %v, want %v (strictly after since, sorted by time)", ids(got), want)
	}
}

func TestSQLite_ListEvents_NewestFirstWithTotal(t *testing.T) {
	s, _ := openTestDB(t)
	saveAll(t, s, ev("1", "10.0.0.1", 0), ev("2", "10.0.0.2", 0), ev("3", "10.0.0.1", time.Second))

	all, _ := s.ListEvents(context.Background(), ListQuery{Limit: 2})
	if !slices.Equal(ids(all.Items), []string{"3", "2"}) || all.Total != 3 {
		t.Errorf("got %v total %d", ids(all.Items), all.Total)
	}
	byIP, _ := s.ListEvents(context.Background(), ListQuery{IP: "10.0.0.1", Limit: 10})
	if !slices.Equal(ids(byIP.Items), []string{"3", "1"}) || byIP.Total != 2 {
		t.Errorf("got %v total %d", ids(byIP.Items), byIP.Total)
	}
}

func TestSQLite_RoundTripsAllFields(t *testing.T) {
	ctx := context.Background()
	s, _ := openTestDB(t)
	in := domain.Event{
		ID: "e1", IP: "2001:db8::1", Timestamp: t0.Add(123 * time.Nanosecond), EventType: domain.EventDNSQuery,
		UserAgent: "ua", Path: "/x?a=<script>", Port: 53, StatusCode: 200, Message: "m'; DROP TABLE events;--",
		Metadata: map[string]string{"base_domain": "example.com"}, DstIP: "192.0.2.1", SrcPort: 5353,
		Protocol: "udp", Direction: domain.DirectionOutbound, Domain: "a.example.com",
	}
	saveAll(t, s, in)
	got, _ := s.ListEvents(ctx, ListQuery{Limit: 1})
	if len(got.Items) != 1 {
		t.Fatalf("got %d items", len(got.Items))
	}
	out := got.Items[0]
	if !out.Timestamp.Equal(in.Timestamp) {
		t.Errorf("timestamp %v, want %v", out.Timestamp, in.Timestamp)
	}
	out.Timestamp = in.Timestamp
	if fmt.Sprintf("%+v", out) != fmt.Sprintf("%+v", in) {
		t.Errorf("round trip changed the event:\n got %+v\nwant %+v", out, in)
	}
}

func TestSQLite_PersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	s, path := openTestDB(t)
	saveAll(t, s, ev("e1", "10.0.0.1", 0))
	_ = s.SaveAlert(ctx, domain.Alert{ID: "a1", IP: "10.0.0.1", Timestamp: t0, Severity: domain.SeverityHigh, TriggerRule: "BruteForce"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if st := s2.Stats(); st.Events != 1 || st.EventIPs != 1 || st.Alerts != 1 {
		t.Errorf("stats after reopen: %+v", st)
	}
	alerts, _ := s2.FindAlertsByIPSince(ctx, "10.0.0.1", t0.Add(-time.Hour))
	if len(alerts) != 1 || alerts[0].TriggerRule != "BruteForce" || alerts[0].Severity != domain.SeverityHigh {
		t.Errorf("alerts after reopen: %+v", alerts)
	}
}

func TestSQLite_WritesBufferedEventsInBackground(t *testing.T) {
	s, path := openTestDB(t)
	saveAll(t, s, ev("e1", "10.0.0.1", 0))

	// A second connection sees only committed rows, without flushing.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM events").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("buffered event was not written")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSQLite_FullBatchReturnsWriteError(t *testing.T) {
	s, _ := openTestDB(t)
	_ = s.writer.Close() // every write fails from now on

	var err error
	for i := range eventBatchSize {
		if err = s.SaveEvent(context.Background(), ev(fmt.Sprint(i), "10.0.0.1", 0)); err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("expected the caller filling the batch to get the write error")
	}
	if st := s.Stats(); st.Events != 0 {
		t.Errorf("lost events still counted: %+v", st)
	}
}

func TestSQLite_ConcurrentWritersAndReaders(t *testing.T) {
	ctx := context.Background()
	s, _ := openTestDB(t, WithRetention(0, 0))
	const writers, perWriter = 8, 400

	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range perWriter {
				ip := fmt.Sprintf("10.0.%d.%d", w, i%5)
				if err := s.SaveEvent(ctx, ev(fmt.Sprintf("%d-%d", w, i), ip, time.Duration(i)*time.Millisecond)); err != nil {
					t.Error(err)
					return
				}
				if i%50 == 0 {
					_ = s.SaveAlert(ctx, domain.Alert{ID: fmt.Sprintf("a%d-%d", w, i), IP: ip, Timestamp: t0})
					if _, err := s.ListEvents(ctx, ListQuery{IP: ip, Limit: 10}); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	wg.Go(func() {
		for range 20 {
			if err := s.Prune(t0); err != nil {
				t.Error(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	wg.Wait()

	all, _ := s.ListEvents(ctx, ListQuery{Limit: 1})
	if all.Total != writers*perWriter {
		t.Errorf("stored %d events, want %d", all.Total, writers*perWriter)
	}
	_ = s.Prune(t0)
	if st := s.Stats(); st.Events != writers*perWriter || st.EventIPs != writers*5 || st.Alerts != writers*perWriter/50 {
		t.Errorf("stats: %+v", st)
	}
}

func TestSQLite_RejectsNewerSchema(t *testing.T) {
	_, path := openTestDB(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", len(migrations)+1)); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	if _, err := OpenSQLiteStore(context.Background(), path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("expected an error for a newer schema, got %v", err)
	}
}

func TestSQLite_Prune_RetentionAndCapacity(t *testing.T) {
	ctx := context.Background()
	var evicted []string
	s, _ := openTestDB(t, WithRetention(time.Hour, 2*time.Hour), WithCapacity(2, 0),
		WithEvictionFunc(func(kind, reason string, n int) {
			evicted = append(evicted, fmt.Sprintf("%s/%s/%d", kind, reason, n))
		}))
	saveAll(t, s,
		ev("old", "10.0.0.1", -90*time.Minute),
		ev("first", "10.0.0.3", -10*time.Minute), // inserted first among the fresh ones: beyond capacity
		ev("new", "10.0.0.1", -30*time.Minute),
		ev("newest", "10.0.0.2", -20*time.Minute),
	)
	_ = s.SaveAlert(ctx, domain.Alert{ID: "a-old", IP: "10.0.0.1", Timestamp: t0.Add(-3 * time.Hour)})
	_ = s.SaveAlert(ctx, domain.Alert{ID: "a-new", IP: "10.0.0.1", Timestamp: t0.Add(-90 * time.Minute)})

	if err := s.Prune(t0); err != nil {
		t.Fatal(err)
	}

	all, _ := s.ListEvents(ctx, ListQuery{Limit: 10})
	if !slices.Equal(ids(all.Items), []string{"newest", "new"}) || all.Total != 2 {
		t.Errorf("events after prune: %v (total %d)", ids(all.Items), all.Total)
	}
	alerts, _ := s.ListAlerts(ctx, ListQuery{Limit: 10})
	if len(alerts.Items) != 1 || alerts.Items[0].ID != "a-new" {
		t.Errorf("alerts after prune: %+v", alerts.Items)
	}
	if st := s.Stats(); st.Events != 2 || st.EventIPs != 2 || st.Alerts != 1 {
		t.Errorf("stats after prune: %+v", st)
	}
	slices.Sort(evicted)
	if want := []string{"alert/retention/1", "event/capacity/1", "event/retention/1"}; !slices.Equal(evicted, want) {
		t.Errorf("eviction callback got %v, want %v", evicted, want)
	}
}

func TestSQLite_SetAIAnalysis(t *testing.T) {
	ctx := context.Background()
	s, _ := openTestDB(t)
	_ = s.SaveAlert(ctx, domain.Alert{ID: "a1", IP: "10.0.0.1", Timestamp: t0, RelatedRules: []string{"RapidFire"}})
	_ = s.SaveAlert(ctx, domain.Alert{ID: "a2", IP: "10.0.0.1", Timestamp: t0.Add(time.Second)})

	if err := s.SetAIAnalysis(ctx, "10.0.0.1", "a1", domain.AIAnalysis{Status: domain.AIStatusCompleted, Verdict: "benign"}); err != nil {
		t.Fatal(err)
	}
	after, _ := s.ListAlerts(ctx, ListQuery{IP: "10.0.0.1", Limit: 10})
	a1 := after.Items[1]
	if a1.ID != "a1" || a1.AIAnalysis == nil || a1.AIAnalysis.Verdict != "benign" || after.Items[0].AIAnalysis != nil {
		t.Errorf("analysis not attached to a1 only: %+v", after.Items)
	}
	if !slices.Equal(a1.RelatedRules, []string{"RapidFire"}) {
		t.Errorf("other fields changed: %+v", a1)
	}

	for _, key := range [][2]string{{"10.0.0.1", "missing"}, {"10.0.0.2", "a1"}} {
		if err := s.SetAIAnalysis(ctx, key[0], key[1], domain.AIAnalysis{}); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v: expected ErrNotFound, got %v", key, err)
		}
	}
}

// TestSQLite_MatchesMemoryStore runs random operations against both stores
// and compares every query result. Capacity is left out: MemoryStore enforces
// it on insert, SQLiteStore when pruning.
func TestSQLite_MatchesMemoryStore(t *testing.T) {
	ctx := context.Background()
	retention := WithRetention(10*time.Minute, 20*time.Minute)
	mem := NewMemoryStore(retention, WithCapacity(0, 0))
	db, _ := openTestDB(t, retention, WithCapacity(0, 0))
	rng := rand.New(rand.NewPCG(3, 4))
	types := []domain.EventType{domain.EventHTTPRequest, domain.EventFailedLogin, domain.EventDNSQuery}
	severities := []domain.Severity{domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical}
	rules := []string{"BruteForce", "PortScan", "XSS"}

	for step := range 3000 {
		ip := fmt.Sprintf("10.0.0.%d", rng.IntN(8))
		ts := t0.Add(time.Duration(step-rng.IntN(30)) * time.Second) // mostly in order, with jitter
		switch op := rng.IntN(100); {
		case op < 70:
			e := domain.Event{ID: fmt.Sprint(step), IP: ip, Timestamp: ts, EventType: types[rng.IntN(len(types))]}
			_ = mem.SaveEvent(ctx, e)
			if err := db.SaveEvent(ctx, e); err != nil {
				t.Fatal(err)
			}
		case op < 80:
			a := domain.Alert{ID: fmt.Sprint(step), IP: ip, Timestamp: ts,
				Severity: severities[rng.IntN(len(severities))], TriggerRule: rules[rng.IntN(len(rules))]}
			_ = mem.SaveAlert(ctx, a)
			if err := db.SaveAlert(ctx, a); err != nil {
				t.Fatal(err)
			}
		case op < 83:
			now := t0.Add(time.Duration(step) * time.Second)
			_ = mem.Prune(now)
			if err := db.Prune(now); err != nil {
				t.Fatal(err)
			}
		default:
			since := ts.Add(-time.Duration(rng.IntN(600)) * time.Second)
			m, _ := mem.FindEventsByIPSince(ctx, ip, since)
			d, _ := db.FindEventsByIPSince(ctx, ip, since)
			if !slices.Equal(ids(m), ids(d)) {
				t.Fatalf("step %d: FindEventsByIPSince = %v, memory %v", step, ids(d), ids(m))
			}
			filter := ListQuery{EventType: types[rng.IntN(len(types))], MinSeverity: severities[rng.IntN(len(severities))], Rule: rules[rng.IntN(len(rules))]}
			queries := []ListQuery{{Limit: 20}, {IP: ip, Limit: 20}, {Limit: 20, EventType: filter.EventType},
				{IP: ip, Limit: 20, MinSeverity: filter.MinSeverity}, {Limit: 20, MinSeverity: filter.MinSeverity, Rule: filter.Rule}}
			for _, q := range queries {
				m, _ := mem.ListEvents(ctx, q)
				d, _ := db.ListEvents(ctx, q)
				if !slices.Equal(ids(m.Items), ids(d.Items)) || m.Total != d.Total {
					t.Fatalf("step %d: ListEvents(%+v) = %v (%d), memory %v (%d)", step, q, ids(d.Items), d.Total, ids(m.Items), m.Total)
				}
				ma, _ := mem.ListAlerts(ctx, q)
				da, _ := db.ListAlerts(ctx, q)
				if fmt.Sprint(ma) != fmt.Sprint(da) {
					t.Fatalf("step %d: ListAlerts(%+v) = %v, memory %v", step, q, da, ma)
				}
			}
			ms, _ := mem.SummarizeAlerts(ctx, since)
			ds, _ := db.SummarizeAlerts(ctx, since)
			if fmt.Sprint(ms) != fmt.Sprint(ds) {
				t.Fatalf("step %d: SummarizeAlerts = %+v, memory %+v", step, ds, ms)
			}
		}
	}
	// SQLiteStore counts distinct IPs when pruning.
	_ = mem.Prune(t0)
	if err := db.Prune(t0); err != nil {
		t.Fatal(err)
	}
	if m, d := mem.Stats(), db.Stats(); m != d {
		t.Errorf("stats = %+v, memory %+v", d, m)
	}
}

// BenchmarkSQLite_SaveEvent measures the cost per event the ingestion path
// pays, including the batched writes.
func BenchmarkSQLite_SaveEvent(b *testing.B) {
	ctx := context.Background()
	s, _ := openTestDB(b)
	e := domain.Event{
		IP: "203.0.113.66", EventType: domain.EventHTTPRequest, Path: "/wp-content/x.php", StatusCode: 404,
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64)", Metadata: map[string]string{"method": "GET", "source": "nginx"},
	}
	b.ResetTimer()
	for i := range b.N {
		e.ID = fmt.Sprint(i)
		e.Timestamp = t0.Add(time.Duration(i) * time.Millisecond)
		if err := s.SaveEvent(ctx, e); err != nil {
			b.Fatal(err)
		}
	}
	if err := s.flush(ctx); err != nil {
		b.Fatal(err)
	}
}
