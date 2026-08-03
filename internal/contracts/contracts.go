// Package contracts defines the versioned messages exchanged by V2 workers
// and the coordinator. These types deliberately contain IDs and facts only;
// they do not expose CodeQL or LLVM implementation objects.
package contracts

import (
	"encoding/json"
	"time"
)

const SchemaVersion = 1

type SeedRecord struct {
	SchemaVersion      int       `json:"schema_version"`
	SeedHash           string    `json:"seed_hash"`
	ModelID            string    `json:"model_id"`
	Size               int64     `json:"size"`
	OriginFuzzer       string    `json:"origin_fuzzer"`
	OriginJob          string    `json:"origin_job"`
	ParentSeedHash     string    `json:"parent_seed_hash,omitempty"`
	FirstSeenAt        time.Time `json:"first_seen_at"`
	ExecutionTimeNanos int64     `json:"canonical_execution_time_ns"`
	EdgeBitmap         []uint32  `json:"edge_bitmap"`
	FunctionBitmap     []uint32  `json:"function_bitmap,omitempty"`
	FrontierBitmap     []uint32  `json:"frontier_bitmap,omitempty"`
	CrashSignature     string    `json:"crash_signature,omitempty"`
}

type JobDispatch struct {
	SchemaVersion        int      `json:"schema_version"`
	JobID                string   `json:"job_id"`
	ModelID              string   `json:"model_id"`
	DispatchStateVersion uint64   `json:"dispatch_state_version"`
	RegionID             string   `json:"region_id"`
	FrontierIDs          []string `json:"frontier_ids"`
	FuzzerID             string   `json:"fuzzer_id"`
	SeedHashes           []string `json:"seed_hashes"`
	DictionaryTokens     []string `json:"dictionary_tokens,omitempty"`
	TimeBudgetSeconds    int64    `json:"time_budget_seconds"`
	MaxExecutions        uint64   `json:"max_executions,omitempty"`
}

type JobResult struct {
	SchemaVersion     int      `json:"schema_version"`
	JobID             string   `json:"job_id"`
	OutputSeedHashes  []string `json:"output_seed_hashes"`
	InputUnionBitmap  []uint32 `json:"input_union_bitmap"`
	OutputUnionBitmap []uint32 `json:"output_union_bitmap"`
	CrossedFrontiers  []string `json:"crossed_frontier_ids,omitempty"`
	Executions        uint64   `json:"executions"`
	ExecsPerSecond    float64  `json:"execs_per_second"`
	WallTimeNanos     int64    `json:"wall_time_ns"`
	RestartNanos      int64    `json:"restart_overhead_ns"`
	Status            string   `json:"status"`
}

type JobFeedback struct {
	SchemaVersion          int      `json:"schema_version"`
	JobID                  string   `json:"job_id"`
	MergedStateVersion     uint64   `json:"merged_state_version"`
	JobDeltaBitmap         []uint32 `json:"job_delta_bitmap"`
	NovelDeltaBitmap       []uint32 `json:"novel_delta_bitmap"`
	ConcurrentDuplicateMap []uint32 `json:"concurrent_duplicate_bitmap"`
	CrossedFrontiers       []string `json:"crossed_frontier_ids,omitempty"`
}

type Event struct {
	SchemaVersion int             `json:"schema_version"`
	Sequence      uint64          `json:"sequence"`
	Type          string          `json:"type"`
	OccurredAt    time.Time       `json:"occurred_at"`
	ModelID       string          `json:"model_id"`
	JobID         string          `json:"job_id,omitempty"`
	StateVersion  uint64          `json:"state_version"`
	Payload       json.RawMessage `json:"payload,omitempty"`
}
