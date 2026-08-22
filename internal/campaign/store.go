// Package campaign provides SQLite-persisted campaign state.
// It stores seed records, job coverage attribution, frontier state,
// and an append-only event log in campaign.sqlite.
//
// The store uses the sqlite3 CLI for SQL execution (no external Go
// dependency required). All bitmap values are serialized as
// space-separated uint32 lists in TEXT columns for simplicity;
// a binary representation can replace this later.
package campaign

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/grubwithu/orchestra/internal/contracts"
)

// Store manages campaign.sqlite via the sqlite3 CLI.
type Store struct {
	dbPath    string
	sqlite3   string
	campaignID string
	modelID   string
}

// New creates a new campaign store. If create is true, it initializes
// a fresh database from the schema file.
func New(dbPath, schemaPath, campaignID, modelID string) (*Store, error) {
	s := &Store{
		dbPath:    dbPath,
		sqlite3:   "sqlite3",
		campaignID: campaignID,
		modelID:   modelID,
	}

	// Create fresh database from schema if it doesn't exist.
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		if schemaPath != "" {
			schema, err := os.ReadFile(schemaPath)
			if err != nil {
				return nil, fmt.Errorf("read schema: %w", err)
			}
			if err := s.execSQL(string(schema)); err != nil {
				return nil, fmt.Errorf("create database: %w", err)
			}
		}
		// Insert campaign row.
		now := time.Now().UTC().Format(time.RFC3339)
		s.execSQL(fmt.Sprintf(
			"INSERT INTO campaigns (campaign_id, model_id, started_at, rng_seed, state_version) VALUES ('%s', '%s', '%s', 0, 0);",
			escape(campaignID), escape(modelID), now))
	}

	return s, nil
}

// PutSeedRecord persists a Seed Record.
func (s *Store) PutSeedRecord(sr contracts.SeedRecord) error {
	bitmapStr := bitmapToText(sr.EdgeBitmap)
	funcStr := bitmapToText(sr.FunctionBitmap)
	frontierStr := bitmapToText(sr.FrontierBitmap)
	now := time.Now().UTC().Format(time.RFC3339)
	sql := fmt.Sprintf(
		"INSERT OR IGNORE INTO seeds (seed_hash, model_id, size, origin_fuzzer, origin_job, parent_seed_hash, first_seen_at, canonical_execution_time_ns, edge_bitmap, function_bitmap, frontier_bitmap, crash_signature) VALUES ('%s', '%s', %d, '%s', '%s', '%s', '%s', %d, '%s', '%s', '%s', '%s');",
		escape(sr.SeedHash), escape(sr.ModelID), sr.Size,
		escape(sr.OriginFuzzer), escape(sr.OriginJob),
		escape(sr.ParentSeedHash), now, sr.ExecutionTimeNanos,
		bitmapStr, funcStr, frontierStr, escape(sr.CrashSignature))
	return s.execSQL(sql)
}

// HasSeed checks if a seed measurement exists.
func (s *Store) HasSeed(seedHash string) (bool, error) {
	output, err := s.querySQL(fmt.Sprintf(
		"SELECT COUNT(*) FROM seeds WHERE model_id='%s' AND seed_hash='%s';",
		escape(s.modelID), escape(seedHash)))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(output) == "1" || strings.TrimSpace(output) != "0" && strings.TrimSpace(output) != "", nil
}

// GetSeedEdgeBitmap retrieves the edge bitmap for a seed.
func (s *Store) GetSeedEdgeBitmap(seedHash string) ([]uint32, error) {
	output, err := s.querySQL(fmt.Sprintf(
		"SELECT edge_bitmap FROM seeds WHERE model_id='%s' AND seed_hash='%s';",
		escape(s.modelID), escape(seedHash)))
	if err != nil {
		return nil, err
	}
	return textToBitmap(strings.TrimSpace(output)), nil
}

// PutJobCoverage persists job coverage attribution.
func (s *Store) PutJobCoverage(jobID string, feedback contracts.JobFeedback) error {
	sql := fmt.Sprintf(
		"INSERT OR REPLACE INTO job_coverage (job_id, input_union_bitmap, output_union_bitmap, job_delta_bitmap, novel_delta_bitmap, concurrent_duplicate_bitmap) VALUES ('%s', '', '', '%s', '%s', '%s');",
		escape(jobID),
		bitmapToText(feedback.JobDeltaBitmap),
		bitmapToText(feedback.NovelDeltaBitmap),
		bitmapToText(feedback.ConcurrentDuplicateMap))
	return s.execSQL(sql)
}

// UpdateFrontierState updates a frontier's state.
func (s *Store) UpdateFrontierState(frontierKey, state string, stateVersion uint64, evidence string) error {
	sql := fmt.Sprintf(
		"INSERT OR REPLACE INTO frontier_state (campaign_id, frontier_key, state, first_activated_version, last_updated_version, evidence_json) VALUES ('%s', '%s', '%s', %d, %d, '%s');",
		escape(s.campaignID), escape(frontierKey), escape(state),
		stateVersion, stateVersion, escape(evidence))
	return s.execSQL(sql)
}

// AppendEvent appends an event to the append-only event log.
func (s *Store) AppendEvent(eventType, jobID string, stateVersion uint64, payload any) error {
	payloadJSON := "{}"
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
		payloadJSON = string(data)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	jobClause := "NULL"
	if jobID != "" {
		jobClause = fmt.Sprintf("'%s'", escape(jobID))
	}
	sql := fmt.Sprintf(
		"INSERT INTO events (campaign_id, event_type, occurred_at, model_id, job_id, state_version, payload_json) VALUES ('%s', '%s', '%s', '%s', %s, %d, '%s');",
		escape(s.campaignID), escape(eventType), now,
		escape(s.modelID), jobClause, stateVersion, escape(payloadJSON))
	return s.execSQL(sql)
}

// Close flushes and closes the store.
func (s *Store) Close() error {
	return nil
}

// execSQL executes SQL via the sqlite3 CLI.
func (s *Store) execSQL(sql string) error {
	cmd := exec.Command(s.sqlite3, s.dbPath)
	cmd.Stdin = strings.NewReader(sql)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sqlite3: %w\n%s", err, string(output))
	}
	return nil
}

// querySQL executes a SELECT and returns the first column as text.
func (s *Store) querySQL(sql string) (string, error) {
	cmd := exec.Command(s.sqlite3, s.dbPath, sql)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("sqlite3: %w", err)
	}
	return string(output), nil
}

// bitmapToText serializes a uint32 slice as space-separated text.
func bitmapToText(edges []uint32) string {
	if len(edges) == 0 {
		return ""
	}
	parts := make([]string, len(edges))
	for i, e := range edges {
		parts[i] = fmt.Sprintf("%d", e)
	}
	return strings.Join(parts, " ")
}

// textToBitmap deserializes space-separated text to a uint32 slice.
func textToBitmap(s string) []uint32 {
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	edges := make([]uint32, 0, len(parts))
	for _, p := range parts {
		var v uint32
		_, err := fmt.Sscanf(p, "%d", &v)
		if err != nil {
			continue
		}
		edges = append(edges, v)
	}
	return edges
}

// escape escapes a string for SQL.
func escape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
