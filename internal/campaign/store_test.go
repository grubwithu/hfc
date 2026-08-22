package campaign

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grubwithu/orchestra/internal/contracts"
)

func TestStoreSeedRecordRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "campaign.sqlite")
	schemaPath := "../../schema/campaign.sql"

	store, err := New(dbPath, schemaPath, "test-campaign", "test-model")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	// Store a seed record.
	sr := contracts.SeedRecord{
		SchemaVersion:      1,
		SeedHash:           "abc123",
		ModelID:            "test-model",
		Size:               42,
		OriginFuzzer:       "libfuzzer",
		OriginJob:          "job1",
		FirstSeenAt:        time.Now().UTC(),
		ExecutionTimeNanos: 1000000,
		EdgeBitmap:         []uint32{1, 2, 3, 100, 200},
		CrashSignature:     "",
	}

	if err := store.PutSeedRecord(sr); err != nil {
		t.Fatalf("put seed record: %v", err)
	}

	// Verify it exists.
	has, err := store.HasSeed("abc123")
	if err != nil {
		t.Fatalf("has seed: %v", err)
	}
	if !has {
		t.Fatal("expected seed to exist in store")
	}

	// Verify at-most-once: put again should not error (INSERT OR IGNORE).
	if err := store.PutSeedRecord(sr); err != nil {
		t.Fatalf("re-put seed record: %v", err)
	}

	// Retrieve edge bitmap.
	edges, err := store.GetSeedEdgeBitmap("abc123")
	if err != nil {
		t.Fatalf("get seed edges: %v", err)
	}
	if len(edges) != 5 {
		t.Fatalf("expected 5 edges, got %d: %v", len(edges), edges)
	}
	t.Logf("Retrieved seed edges: %v", edges)
}

func TestStoreEventLog(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "campaign.sqlite")
	schemaPath := "../../schema/campaign.sql"

	store, err := New(dbPath, schemaPath, "test-campaign-2", "test-model-2")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	// Append events.
	events := []struct {
		eventType string
		jobID     string
		stateVer  uint64
	}{
		{"campaign_started", "", 0},
		{"job_dispatched", "job1", 0},
		{"seed_observed", "job1", 0},
		{"seed_measured", "job1", 0},
		{"job_completed", "job1", 1},
		{"coverage_merged", "job1", 1},
		{"frontier_updated", "job1", 1},
		{"campaign_finished", "", 1},
	}

	for _, e := range events {
		if err := store.AppendEvent(e.eventType, e.jobID, e.stateVer, nil); err != nil {
			t.Fatalf("append event %s: %v", e.eventType, err)
		}
	}

	// Verify event count.
	output, err := store.querySQL("SELECT COUNT(*) FROM events WHERE campaign_id='test-campaign-2';")
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	count := strings.TrimSpace(output)
	if count != "8" {
		t.Errorf("expected 8 events, got %s", count)
	}
	t.Logf("Appended %s events to event log", count)
}

func TestStoreFrontierState(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "campaign.sqlite")
	schemaPath := "../../schema/campaign.sql"

	store, err := New(dbPath, schemaPath, "test-campaign-3", "test-model-3")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	// Update frontier states.
	if err := store.UpdateFrontierState("f1", "active", 1, `{"edge":"true"}`); err != nil {
		t.Fatalf("update frontier: %v", err)
	}
	if err := store.UpdateFrontierState("f1", "crossed", 2, `{"edge":"both"}`); err != nil {
		t.Fatalf("update frontier 2: %v", err)
	}

	// Verify.
	output, err := store.querySQL("SELECT state FROM frontier_state WHERE campaign_id='test-campaign-3' AND frontier_key='f1';")
	if err != nil {
		t.Fatalf("query frontier: %v", err)
	}
	state := strings.TrimSpace(output)
	if state != "crossed" {
		t.Errorf("expected state='crossed', got '%s'", state)
	}
	t.Logf("Frontier state: %s", state)
}
