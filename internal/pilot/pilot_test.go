package pilot

import (
	"context"
	"testing"
	"time"

	"github.com/grubwithu/orchestra/internal/contracts"
	"github.com/grubwithu/orchestra/internal/frontier"
	"github.com/grubwithu/orchestra/internal/probe"
)

// mockProbe is a test probe that returns predefined edges.
type mockProbe struct {
	seedEdges map[string][]uint32
}

func (m *mockProbe) Measure(ctx context.Context, seedPath string) (probe.Result, error) {
	return probe.Result{
		EdgeIDs:   m.seedEdges["default"],
		ExitStatus: "ok",
	}, nil
}

func TestPilotSingleTarget(t *testing.T) {
	frontiers := []frontier.Definition{
		{
			Key:                    "f1",
			MappingStatus:          "exact",
			InputDependencyClass:   "local_direct",
			TrueEdgeID:             100,
			FalseEdgeID:            200,
			HasUncoveredDownstream: true,
		},
		{
			Key:                    "f2",
			MappingStatus:          "exact",
			InputDependencyClass:   "local_direct",
			TrueEdgeID:             300,
			FalseEdgeID:            400,
			HasUncoveredDownstream: true,
		},
	}

	cfg := &PilotConfig{
		ModelID:       "pilot-model-001",
		SeedBatchSize: 4,
		Targets: []TargetConfig{
			{
				ModelID:    "pilot-model-001",
				FuzzerID:   "libfuzzer",
				FuzzTarget: "test_fuzzer",
				Frontiers:  frontiers,
				Probe:      &mockProbe{},
			},
		},
	}

	ctx := context.Background()
	results, err := cfg.Run(ctx)
	if err != nil {
		t.Fatalf("pilot run: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.SeedsMeasured != 2 {
		t.Errorf("expected 2 seeds measured, got %d", r.SeedsMeasured)
	}
	if r.Dispatches != 2 {
		t.Errorf("expected 2 dispatches, got %d", r.Dispatches)
	}
	if r.FrontiersTracked != 2 {
		t.Errorf("expected 2 frontiers tracked, got %d", r.FrontiersTracked)
	}

	t.Logf("Pilot result: target=%s, seeds=%d, dispatches=%d, crossings=%d, duration=%v",
		r.Target, r.SeedsMeasured, r.Dispatches, r.Crossings, r.Duration)
	_ = contracts.SeedRecord{} // keep import
	_ = time.Now             // keep import
}

func TestPilotMultiTargetMultiFuzzer(t *testing.T) {
	// Two targets (zlib and jsoncpp), two mechanism-distinct fuzzers
	// (libfuzzer and afl). Each target has its own frontier set.
	target1Frontiers := []frontier.Definition{
		{
			Key: "t1-f1", MappingStatus: "exact",
			InputDependencyClass: "local_direct",
			TrueEdgeID: 100, FalseEdgeID: 200,
			HasUncoveredDownstream: true,
		},
	}
	target2Frontiers := []frontier.Definition{
		{
			Key: "t2-f1", MappingStatus: "exact",
			InputDependencyClass: "local_direct",
			TrueEdgeID: 300, FalseEdgeID: 400,
			HasUncoveredDownstream: true,
		},
		{
			Key: "t2-f2", MappingStatus: "exact",
			InputDependencyClass: "local_direct",
			TrueEdgeID: 500, FalseEdgeID: 600,
			HasUncoveredDownstream: true,
		},
	}

	cfg := &PilotConfig{
		ModelID: "pilot-multi-model",
		Targets: []TargetConfig{
			{
				ModelID: "pilot-multi-model", FuzzerID: "libfuzzer",
				FuzzTarget: "zlib_uncompress_fuzzer",
				Frontiers: target1Frontiers, Probe: &mockProbe{},
			},
			{
				ModelID: "pilot-multi-model", FuzzerID: "afl",
				FuzzTarget: "jsoncpp_fuzzer",
				Frontiers: target2Frontiers, Probe: &mockProbe{},
			},
		},
	}

	ctx := context.Background()
	results, err := cfg.Run(ctx)
	if err != nil {
		t.Fatalf("pilot run: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Target 1: 1 frontier → 1 seed, 1 dispatch
	if results[0].SeedsMeasured != 1 {
		t.Errorf("target1 seeds: expected 1, got %d", results[0].SeedsMeasured)
	}
	if results[0].Dispatches != 1 {
		t.Errorf("target1 dispatches: expected 1, got %d", results[0].Dispatches)
	}

	// Target 2: 2 frontiers → 2 seeds, 2 dispatches
	if results[1].SeedsMeasured != 2 {
		t.Errorf("target2 seeds: expected 2, got %d", results[1].SeedsMeasured)
	}
	if results[1].Dispatches != 2 {
		t.Errorf("target2 dispatches: expected 2, got %d", results[1].Dispatches)
	}

	// Both targets should have at least 1 crossing (seed covers both
	// true and false edge in the simple mock).
	for i, r := range results {
		if r.Crossings == 0 {
			t.Errorf("target %d: expected at least 1 crossing, got 0", i)
		}
		t.Logf("Target %d (%s): seeds=%d, dispatches=%d, crossings=%d",
			i, r.Target, r.SeedsMeasured, r.Dispatches, r.Crossings)
	}
}
