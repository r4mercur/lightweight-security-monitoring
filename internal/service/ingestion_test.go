package service_test

import (
	"context"
	"io"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/metrics"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"log/slog"
	"testing"
	"time"
	"uuid"
)

func newIngestion(t *testing.T) (*service.IngestionService, *repository.MemoryStore) {
	t.Helper()
	store := repository.NewMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return service.NewIngestionService(store, store, newEngine(t), nil, metrics.NewMetrics(), logger), store
}

func TestIngest_IDsAreTimeOrderedUUIDs(t *testing.T) {
	ingestion, store := newIngestion(t)
	ctx := context.Background()

	var alertID string
	for i := range 5 {
		alert, err := ingestion.Ingest(ctx, domain.Event{IP: "10.2.0.9", EventType: domain.EventHTTPRequest, Path: "/.env"})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			alertID = alert.ID
		}
	}
	if _, err := ingestion.Ingest(ctx, domain.Event{ID: "client-supplied", IP: "10.2.0.9"}); err != nil {
		t.Fatal(err)
	}

	res, _ := store.ListEvents(ctx, repository.ListQuery{IP: "10.2.0.9", Limit: 10}) // newest first
	if res.Items[0].ID != "client-supplied" {
		t.Errorf("client-supplied ID was replaced: %q", res.Items[0].ID)
	}
	var ids []uuid.UUID
	for _, e := range res.Items[1:] {
		id, err := uuid.Parse(e.ID)
		if err != nil || id[6]>>4 != 7 {
			t.Fatalf("event ID %q is not a version 7 UUID (%v)", e.ID, err)
		}
		ids = append(ids, id)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1].Compare(ids[i]) <= 0 {
			t.Errorf("IDs do not sort by creation: %s is listed before older %s", ids[i-1], ids[i])
		}
	}
	if id, err := uuid.Parse(alertID); err != nil || id[6]>>4 != 7 {
		t.Errorf("alert ID %q is not a version 7 UUID (%v)", alertID, err)
	}
}

func TestIngest_FutureTimestampIsReplaced(t *testing.T) {
	ingestion, store := newIngestion(t)
	future := time.Now().Add(24 * time.Hour)

	if _, err := ingestion.Ingest(context.Background(), domain.Event{IP: "10.2.0.1", Timestamp: future}); err != nil {
		t.Fatal(err)
	}
	res, _ := store.ListEvents(context.Background(), repository.ListQuery{Limit: 1})
	if got := res.Items[0].Timestamp; got.After(time.Now()) {
		t.Errorf("stored timestamp %v is still in the future", got)
	}
}

func TestIngest_IPSpellingsShareState(t *testing.T) {
	ingestion, _ := newIngestion(t)
	spellings := []string{"2001:db8::1", "2001:DB8::1", "2001:0db8:0:0::1", "2001:db8::0:1", "2001:db8:0::1"}

	var alert *domain.Alert
	for _, ip := range spellings {
		var err error
		alert, err = ingestion.Ingest(context.Background(), domain.Event{IP: ip, EventType: domain.EventFailedLogin})
		if err != nil {
			t.Fatal(err)
		}
	}
	if alert == nil || alert.TriggerRule != "BruteForce" || alert.IP != "2001:db8::1" {
		t.Fatalf("expected BruteForce for the canonical IP after 5 differently spelled attempts, got %+v", alert)
	}
}

func TestIngest_IPv4MappedIPv6IsUnmapped(t *testing.T) {
	ingestion, store := newIngestion(t)
	if _, err := ingestion.Ingest(context.Background(), domain.Event{IP: "::ffff:10.2.0.2"}); err != nil {
		t.Fatal(err)
	}
	res, _ := store.ListEvents(context.Background(), repository.ListQuery{IP: "10.2.0.2", Limit: 1})
	if res.Total != 1 {
		t.Errorf("expected the event under 10.2.0.2, got %d", res.Total)
	}
}

func TestIngest_InvalidIPIsRejected(t *testing.T) {
	ingestion, _ := newIngestion(t)
	if _, err := ingestion.Ingest(context.Background(), domain.Event{IP: "localhost"}); err == nil {
		t.Error("expected an error for an invalid IP")
	}
}
