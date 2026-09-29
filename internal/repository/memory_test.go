package repository

import (
	"context"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func ev(id, ip string, offset time.Duration) domain.Event {
	return domain.Event{ID: id, IP: ip, Timestamp: t0.Add(offset)}
}

func ids(events []domain.Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.ID
	}
	return out
}

func mustSave(t *testing.T, s *MemoryStore, events ...domain.Event) {
	t.Helper()
	for _, e := range events {
		if err := s.SaveEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFindEventsByIPSince_UsesIndexAndSortsByTime(t *testing.T) {
	s := NewMemoryStore()
	mustSave(t, s,
		ev("a1", "10.0.0.1", 0),
		ev("b1", "10.0.0.2", time.Second),
		ev("a3", "10.0.0.1", 3*time.Second),
		ev("a2", "10.0.0.1", 2*time.Second), // out of order
	)

	got, _ := s.FindEventsByIPSince(context.Background(), "10.0.0.1", t0)
	if want := []string{"a2", "a3"}; !slices.Equal(ids(got), want) {
		t.Errorf("got %v, want %v (strictly after since, sorted by time)", ids(got), want)
	}
}

func TestListEvents_NewestFirstWithTotal(t *testing.T) {
	s := NewMemoryStore()
	mustSave(t, s, ev("1", "10.0.0.1", 0), ev("2", "10.0.0.2", 0), ev("3", "10.0.0.1", time.Second))

	all, _ := s.ListEvents(context.Background(), ListQuery{Limit: 2})
	if !slices.Equal(ids(all.Items), []string{"3", "2"}) || all.Total != 3 {
		t.Errorf("got %v total %d", ids(all.Items), all.Total)
	}
	byIP, _ := s.ListEvents(context.Background(), ListQuery{IP: "10.0.0.1", Limit: 10})
	if !slices.Equal(ids(byIP.Items), []string{"3", "1"}) || byIP.Total != 2 {
		t.Errorf("got %v total %d", ids(byIP.Items), byIP.Total)
	}
}

func TestCapacity_EvictsOldestInserted(t *testing.T) {
	var evicted []string
	s := NewMemoryStore(WithCapacity(3, 0), WithEvictionFunc(func(kind, reason string, n int) {
		evicted = append(evicted, fmt.Sprintf("%s/%s/%d", kind, reason, n))
	}))
	mustSave(t, s,
		ev("1", "10.0.0.1", 5*time.Second), // inserted first, although not the oldest timestamp
		ev("2", "10.0.0.1", 0),
		ev("3", "10.0.0.2", 0),
		ev("4", "10.0.0.2", time.Second),
	)

	all, _ := s.ListEvents(context.Background(), ListQuery{Limit: 10})
	if !slices.Equal(ids(all.Items), []string{"4", "3", "2"}) {
		t.Errorf("got %v, want the first inserted event evicted", ids(all.Items))
	}
	if got, _ := s.FindEventsByIPSince(context.Background(), "10.0.0.1", t0.Add(-time.Hour)); !slices.Equal(ids(got), []string{"2"}) {
		t.Errorf("per-IP index still contains evicted event: %v", ids(got))
	}
	if !slices.Equal(evicted, []string{"event/capacity/1"}) {
		t.Errorf("eviction callback got %v", evicted)
	}
}

func TestPrune_RemovesExpiredEventsAndAlerts(t *testing.T) {
	var evicted []string
	s := NewMemoryStore(WithRetention(time.Hour, 2*time.Hour), WithEvictionFunc(func(kind, reason string, n int) {
		evicted = append(evicted, fmt.Sprintf("%s/%s/%d", kind, reason, n))
	}))
	mustSave(t, s, ev("old", "10.0.0.1", -90*time.Minute), ev("new", "10.0.0.1", -30*time.Minute), ev("gone", "10.0.0.2", -61*time.Minute))
	_ = s.SaveAlert(context.Background(), domain.Alert{ID: "a-old", IP: "10.0.0.1", Timestamp: t0.Add(-3 * time.Hour)})
	_ = s.SaveAlert(context.Background(), domain.Alert{ID: "a-new", IP: "10.0.0.1", Timestamp: t0.Add(-90 * time.Minute)})

	s.Prune(t0)

	all, _ := s.ListEvents(context.Background(), ListQuery{Limit: 10})
	if !slices.Equal(ids(all.Items), []string{"new"}) {
		t.Errorf("events after prune: %v", ids(all.Items))
	}
	alerts, _ := s.ListAlerts(context.Background(), ListQuery{Limit: 10})
	if len(alerts.Items) != 1 || alerts.Items[0].ID != "a-new" {
		t.Errorf("alerts after prune: %+v", alerts.Items)
	}
	if st := s.Stats(); st.Events != 1 || st.EventIPs != 1 || st.Alerts != 1 {
		t.Errorf("stats after prune: %+v", st)
	}
	slices.Sort(evicted)
	if want := []string{"alert/retention/1", "event/retention/2"}; !slices.Equal(evicted, want) {
		t.Errorf("eviction callback got %v, want %v", evicted, want)
	}
}

func TestSetAIAnalysis(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	_ = s.SaveAlert(ctx, domain.Alert{ID: "a1", IP: "10.0.0.1", Timestamp: t0})
	_ = s.SaveAlert(ctx, domain.Alert{ID: "a2", IP: "10.0.0.1", Timestamp: t0.Add(time.Second)})

	before, _ := s.ListAlerts(ctx, ListQuery{IP: "10.0.0.1", Limit: 10})
	if err := s.SetAIAnalysis(ctx, "10.0.0.1", "a1", domain.AIAnalysis{Status: domain.AIStatusCompleted, Verdict: "benign"}); err != nil {
		t.Fatal(err)
	}
	after, _ := s.ListAlerts(ctx, ListQuery{IP: "10.0.0.1", Limit: 10})
	if after.Items[1].ID != "a1" || after.Items[1].AIAnalysis == nil || after.Items[1].AIAnalysis.Verdict != "benign" || after.Items[0].AIAnalysis != nil {
		t.Errorf("analysis not attached to a1 only: %+v", after.Items)
	}
	if before.Items[1].AIAnalysis != nil {
		t.Error("alerts handed out before the update must not change")
	}

	for _, key := range [][2]string{{"10.0.0.1", "missing"}, {"10.0.0.2", "a1"}} {
		if err := s.SetAIAnalysis(ctx, key[0], key[1], domain.AIAnalysis{}); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v: expected ErrNotFound, got %v", key, err)
		}
	}
}

// TestIndexedLog_MatchesModel runs random operations against the indexed log
// and a naive slice-based model and compares every query result.
func TestIndexedLog_MatchesModel(t *testing.T) {
	type item struct {
		id  int
		key string
		ts  time.Time
	}
	rng := rand.New(rand.NewPCG(1, 2))
	const capacity = 300
	l := newIndexedLog[int](capacity)
	var model []item // insertion order

	sortedByTime := func(items []item) []item {
		out := slices.Clone(items)
		slices.SortStableFunc(out, func(a, b item) int { return a.ts.Compare(b.ts) })
		return out
	}

	for step := range 20_000 {
		switch op := rng.IntN(100); {
		case op < 85: // add, mostly in order with some jitter
			it := item{id: step, key: fmt.Sprintf("ip%d", rng.IntN(20)), ts: t0.Add(time.Duration(step-rng.IntN(50)) * time.Second)}
			l.add(it.key, it.ts, it.id)
			model = append(model, it)
			if len(model) > capacity {
				model = model[len(model)-capacity:]
			}
		case op < 90: // prune
			cutoff := t0.Add(time.Duration(step-rng.IntN(400)) * time.Second)
			l.pruneBefore(cutoff)
			model = slices.DeleteFunc(model, func(it item) bool { return it.ts.Before(cutoff) })
		default: // query
			key := fmt.Sprintf("ip%d", rng.IntN(20))
			since := t0.Add(time.Duration(step-rng.IntN(300)) * time.Second)
			var want []int
			for _, it := range sortedByTime(model) {
				if it.key == key && it.ts.After(since) {
					want = append(want, it.id)
				}
			}
			if got := l.since(key, since); !slices.Equal(got, want) { // nil and empty compare equal
				t.Fatalf("step %d: since(%s) = %v, want %v", step, key, got, want)
			}

			var newest []int
			for i := len(model) - 1; i >= 0 && len(newest) < 10; i-- {
				newest = append(newest, model[i].id)
			}
			if got, total := l.newest("", 10); !slices.Equal(got, newest) || total != len(model) {
				t.Fatalf("step %d: newest = %v (%d), want %v (%d)", step, got, total, newest, len(model))
			}
		}
		if l.len() != len(model) {
			t.Fatalf("step %d: len = %d, want %d", step, l.len(), len(model))
		}
	}
	// Removed entries must not accumulate in the insertion-order list.
	if len(l.order)-l.head > 2*capacity+1024 {
		t.Errorf("insertion-order list not compacted: %d entries for %d live", len(l.order)-l.head, l.len())
	}
}
