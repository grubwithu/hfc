package replay

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/grubwithu/orchestra/internal/bitmap"
	"github.com/grubwithu/orchestra/internal/frontier"
	"github.com/grubwithu/orchestra/internal/probe"
)

// TestTwoSeedVerticalSlice tests the core T4 requirement:
// - First seed makes a frontier active
// - Second seed crosses it
// - Repeated seed observation does not execute the probe again
//
// This test uses mock edges (not a real fuzzer binary) to verify the
// replay/coordinator logic without Docker dependency.
func TestTwoSeedVerticalSlice(t *testing.T) {
	// Create a simple frontier with two edges.
	trueEdge := uint32(100)
	falseEdge := uint32(200)
	frontiers := []frontier.Definition{
		{
			Key:                  "test-frontier",
			MappingStatus:        "exact",
			InputDependencyClass: "local_direct",
			TrueEdgeID:           trueEdge,
			FalseEdgeID:          falseEdge,
			HasUncoveredDownstream: true,
		},
	}

	// Create a mock probe that returns predefined edges for each seed.
	// Seed A covers only the true edge (frontier becomes active).
	// Seed B covers only the false edge (frontier becomes crossed).
	mockProbe := &mockProbe{
		results: map[string]probe.Result{
			"seedA": {EdgeIDs: []uint32{trueEdge, 50, 51}, ExitStatus: "ok"},
			"seedB": {EdgeIDs: []uint32{falseEdge, 60, 61}, ExitStatus: "ok"},
		},
	}

	store := probe.NewMemoryStore()
	cr := &CanonicalReplay{
		ModelID:   "test-model",
		Probe:     mockProbe,
		Store:     store,
		Frontiers: frontiers,
	}

	ctx := context.Background()

	// Create temp seed files.
	tmpDir := t.TempDir()
	seedA := filepath.Join(tmpDir, "seedA")
	seedB := filepath.Join(tmpDir, "seedB")
	os.WriteFile(seedA, []byte("AAAA"), 0o644)
	os.WriteFile(seedB, []byte("BBBB"), 0o644)

	// Step 1: Measure seed A — should cover true edge only.
	m1, err := cr.MeasureSeed(ctx, seedA, "test-fuzzer", "job1")
	if err != nil {
		t.Fatalf("measure seed A: %v", err)
	}
	coverageA := bitmap.FromSlice(m1.SeedRecord.EdgeBitmap)
	active, crossed, unseen := cr.EvaluateFrontiers(coverageA)

	if len(crossed) > 0 {
		t.Errorf("seed A should not cross any frontier, got crossed=%v", crossed)
	}
	if len(active) != 1 || active[0] != "test-frontier" {
		t.Errorf("seed A should make test-frontier active, got active=%v", active)
	}
	if len(unseen) > 0 {
		t.Errorf("no frontiers should be unseen after seed A, got unseen=%v", unseen)
	}
	t.Logf("After seed A: active=%v, crossed=%v, unseen=%v", active, crossed, unseen)

	// Step 2: Measure seed B — should cover false edge too, crossing the frontier.
	m2, err := cr.MeasureSeed(ctx, seedB, "test-fuzzer", "job2")
	if err != nil {
		t.Fatalf("measure seed B: %v", err)
	}

	// Combined coverage = A ∪ B.
	coverageAB := coverageA.Union(bitmap.FromSlice(m2.SeedRecord.EdgeBitmap))
	active2, crossed2, unseen2 := cr.EvaluateFrontiers(coverageAB)

	if len(crossed2) != 1 || crossed2[0] != "test-frontier" {
		t.Errorf("seed B should cross test-frontier, got crossed=%v", crossed2)
	}
	if len(active2) > 0 {
		t.Errorf("no frontiers should remain active after seed B, got active=%v", active2)
	}
	if len(unseen2) > 0 {
		t.Errorf("no frontiers should be unseen after seed B, got unseen=%v", unseen2)
	}
	t.Logf("After seed A+B: active=%v, crossed=%v, unseen=%v", active2, crossed2, unseen2)

	// Step 3: Re-measure seed A — should NOT execute the probe again.
	mockProbe.callCount = 0
	_, err = cr.MeasureSeed(ctx, seedA, "test-fuzzer", "job3")
	if err != nil {
		t.Fatalf("re-measure seed A: %v", err)
	}
	if mockProbe.callCount > 0 {
		t.Errorf("probe was called again for already-measured seed (callCount=%d)", mockProbe.callCount)
	}
	t.Log("Re-measure seed A: probe NOT called (at-most-once verified)")
}

// TestFrontierTransitions tests the DeriveFrontierTransitions function.
func TestFrontierTransitions(t *testing.T) {
	trueEdge := uint32(100)
	falseEdge := uint32(200)
	frontiers := []frontier.Definition{
		{
			Key:                  "f1",
			MappingStatus:        "exact",
			InputDependencyClass: "local_direct",
			TrueEdgeID:           trueEdge,
			FalseEdgeID:          falseEdge,
			HasUncoveredDownstream: true,
		},
	}

	cr := &CanonicalReplay{
		ModelID:   "test-model",
		Frontiers: frontiers,
	}

	// Empty -> empty: no transitions.
	active, crossed := cr.DeriveFrontierTransitions(
		bitmap.FromSlice(nil),
		bitmap.FromSlice(nil))
	if len(active) != 0 || len(crossed) != 0 {
		t.Errorf("empty->empty should have no transitions")
	}

	// Empty -> trueEdge: frontier becomes active.
	active, crossed = cr.DeriveFrontierTransitions(
		bitmap.FromSlice(nil),
		bitmap.FromSlice([]uint32{trueEdge}))
	if len(active) != 1 || active[0] != "f1" {
		t.Errorf("empty->trueEdge should make f1 active, got active=%v", active)
	}
	if len(crossed) != 0 {
		t.Errorf("empty->trueEdge should not cross, got crossed=%v", crossed)
	}

	// trueEdge -> trueEdge+falseEdge: frontier becomes crossed.
	active, crossed = cr.DeriveFrontierTransitions(
		bitmap.FromSlice([]uint32{trueEdge}),
		bitmap.FromSlice([]uint32{trueEdge, falseEdge}))
	if len(active) != 0 {
		t.Errorf("trueEdge->both should not newly activate, got active=%v", active)
	}
	if len(crossed) != 1 || crossed[0] != "f1" {
		t.Errorf("trueEdge->both should cross f1, got crossed=%v", crossed)
	}
}

// mockProbe is a test probe that returns predefined results.
type mockProbe struct {
	results    map[string]probe.Result
	callCount  int
}

func (m *mockProbe) Measure(ctx context.Context, seedPath string) (probe.Result, error) {
	m.callCount++
	name := filepath.Base(seedPath)
	if result, ok := m.results[name]; ok {
		return result, nil
	}
	return probe.Result{ExitStatus: "ok"}, nil
}
