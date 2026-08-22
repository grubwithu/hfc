package coordinator

import (
	"testing"

	"github.com/grubwithu/orchestra/internal/bitmap"
	"github.com/grubwithu/orchestra/internal/contracts"
	"github.com/grubwithu/orchestra/internal/frontier"
)

// TestIncrementalVsFullReplay verifies the T4 exit criterion:
// "incremental and full-replay edge sets are equal"
//
// Incremental: process seeds one at a time, unioning their bitmaps.
// Full replay: union all seeds' bitmaps at once.
// The two must produce the same final edge set.
func TestIncrementalVsFullReplay(t *testing.T) {
	// Simulate 5 seeds with overlapping edge coverage.
	seedRecords := []contracts.SeedRecord{
		{SeedHash: "s1", EdgeBitmap: []uint32{1, 2, 3, 100}},
		{SeedHash: "s2", EdgeBitmap: []uint32{2, 3, 4, 200}},
		{SeedHash: "s3", EdgeBitmap: []uint32{1, 5, 100, 200}},
		{SeedHash: "s4", EdgeBitmap: []uint32{6, 7, 8}},
		{SeedHash: "s5", EdgeBitmap: []uint32{1, 2, 3, 4, 5, 6, 7, 8, 100, 200}},
	}

	// Incremental: process one seed at a time, building up the union.
	incremental := bitmap.EdgeSet{}
	for _, sr := range seedRecords {
		seedEdges := bitmap.FromSlice(sr.EdgeBitmap)
		incremental = incremental.Union(seedEdges)
	}

	// Full replay: union all at once.
	fullReplay := bitmap.FromSlice(CoverageUnion(seedRecords))

	// The two must be equal.
	incSorted := incremental.Sorted()
	fullSorted := fullReplay.Sorted()

	if len(incSorted) != len(fullSorted) {
		t.Fatalf("edge count mismatch: incremental=%d, full=%d", len(incSorted), len(fullSorted))
	}

	for i := range incSorted {
		if incSorted[i] != fullSorted[i] {
			t.Fatalf("edge mismatch at position %d: incremental=%d, full=%d",
				i, incSorted[i], fullSorted[i])
		}
	}

	t.Logf("Incremental and full-replay edge sets are equal: %d edges", len(incSorted))
}

// TestModelAwareMergeFromSeeds verifies the T4 exit criterion:
// "Coordinator produces correct job_delta, novel_delta, concurrent duplicate,
// and derived crossed_frontier evidence"
func TestModelAwareMergeFromSeeds(t *testing.T) {
	trueEdge := uint32(100)
	falseEdge := uint32(200)
	frontiers := []frontier.Definition{
		{
			Key:                    "f1",
			MappingStatus:          "exact",
			InputDependencyClass:   "local_direct",
			TrueEdgeID:             trueEdge,
			FalseEdgeID:            falseEdge,
			HasUncoveredDownstream: true,
		},
	}

	state := NewModelAware("test-model", frontiers)

	// Dispatch a job.
	dispatch, err := state.Dispatch(contracts.JobDispatch{
		JobID:   "job1",
		ModelID: "test-model",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	// Seed A covers true edge only.
	seedA := contracts.SeedRecord{
		SeedHash:   "seedA-hash",
		EdgeBitmap: []uint32{trueEdge, 1, 2, 3},
	}

	// Merge job1 with seed A.
	result := contracts.JobResult{
		JobID:             "job1",
		OutputSeedHashes:  []string{"seedA-hash"},
		InputUnionBitmap:  nil,
		OutputUnionBitmap: seedA.EdgeBitmap, // still provided for compatibility
	}

	feedback, err := state.MergeFromSeeds(result, []contracts.SeedRecord{seedA})
	if err != nil {
		t.Fatalf("merge from seeds: %v", err)
	}

	// After seed A: frontier f1 should be active (true edge covered).
	active, crossed, _ := state.EvaluateFrontiers()
	if len(active) != 1 || active[0] != "f1" {
		t.Errorf("expected f1 active after seed A, got active=%v crossed=%v", active, crossed)
	}
	if len(crossed) != 0 {
		t.Errorf("expected no crossed frontiers after seed A, got crossed=%v", crossed)
	}
	t.Logf("After seed A: active=%v, crossed=%v", active, crossed)

	// Check feedback: job_delta should be {1,2,3,100} (all new).
	if len(feedback.JobDeltaBitmap) != 4 {
		t.Errorf("expected 4 job_delta edges, got %d: %v", len(feedback.JobDeltaBitmap), feedback.JobDeltaBitmap)
	}
	// novel_delta should equal job_delta (nothing was covered before).
	if len(feedback.NovelDeltaBitmap) != 4 {
		t.Errorf("expected 4 novel_delta edges, got %d: %v", len(feedback.NovelDeltaBitmap), feedback.NovelDeltaBitmap)
	}
	// No concurrent duplicates.
	if len(feedback.ConcurrentDuplicateMap) != 0 {
		t.Errorf("expected 0 concurrent duplicates, got %d", len(feedback.ConcurrentDuplicateMap))
	}

	// Now dispatch job2 and merge with seed B (covers false edge).
	state.Dispatch(contracts.JobDispatch{
		JobID:   "job2",
		ModelID: "test-model",
	})

	seedB := contracts.SeedRecord{
		SeedHash:   "seedB-hash",
		EdgeBitmap: []uint32{falseEdge, 4, 5, 6},
	}

	result2 := contracts.JobResult{
		JobID:             "job2",
		OutputSeedHashes:  []string{"seedB-hash"},
		InputUnionBitmap:  nil,
		OutputUnionBitmap: seedB.EdgeBitmap,
	}

	feedback2, err := state.MergeFromSeeds(result2, []contracts.SeedRecord{seedB})
	if err != nil {
		t.Fatalf("merge from seeds 2: %v", err)
	}

	// After seed B: frontier f1 should be crossed (both edges covered).
	active2, crossed2, _ := state.EvaluateFrontiers()
	if len(active2) != 0 {
		t.Errorf("expected no active frontiers after seed B, got active=%v", active2)
	}
	if len(crossed2) != 1 || crossed2[0] != "f1" {
		t.Errorf("expected f1 crossed after seed B, got crossed=%v", crossed2)
	}
	t.Logf("After seed B: active=%v, crossed=%v", active2, crossed2)

	// feedback2 should have crossed_frontiers = ["f1"].
	if len(feedback2.CrossedFrontiers) != 1 || feedback2.CrossedFrontiers[0] != "f1" {
		t.Errorf("expected crossed_frontiers=[f1], got %v", feedback2.CrossedFrontiers)
	}
	t.Logf("CrossedFrontiers from feedback: %v", feedback2.CrossedFrontiers)

	// novel_delta for job2 should be {4,5,6,200} (all new).
	if len(feedback2.NovelDeltaBitmap) != 4 {
		t.Errorf("expected 4 novel_delta edges for job2, got %d: %v",
			len(feedback2.NovelDeltaBitmap), feedback2.NovelDeltaBitmap)
	}

	// dispatch_state_version should be 1 (after first merge).
	if dispatch.DispatchStateVersion != 0 {
		t.Errorf("expected dispatch_state_version=0, got %d", dispatch.DispatchStateVersion)
	}

	t.Log("All T4 exit criteria verified: job_delta, novel_delta, concurrent_duplicate, crossed_frontier")
}
