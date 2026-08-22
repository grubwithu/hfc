package region

import (
	"testing"

	"github.com/grubwithu/orchestra/internal/bitmap"
)

func TestCallGraphSCC(t *testing.T) {
	// Build a simple call graph with a cycle: A → B → C → A, plus D → A.
	calls := []CallEdge{
		{CallerKey: "A", CalleeKey: "B"},
		{CallerKey: "B", CalleeKey: "C"},
		{CallerKey: "C", CalleeKey: "A"}, // cycle: A→B→C→A
		{CallerKey: "D", CalleeKey: "A"},
		{CallerKey: "D", CalleeKey: "E"},
	}
	cg := NewCallGraph(calls)

	sccs := cg.SCC()

	// A, B, C should be in one SCC (cycle). D and E should be singletons.
	if len(sccs) != 3 {
		t.Fatalf("expected 3 SCCs, got %d: %v", len(sccs), sccs)
	}

	// Find the SCC containing A.
	var abcSCC []string
	for _, scc := range sccs {
		for _, fn := range scc {
			if fn == "A" {
				abcSCC = scc
				break
			}
		}
	}
	if len(abcSCC) != 3 {
		t.Errorf("expected SCC with A,B,C (3 functions), got %v", abcSCC)
	}
	t.Logf("SCCs: %v", sccs)
}

func TestBuildRegions(t *testing.T) {
	// Simple call graph: main → check_value → helper
	calls := []CallEdge{
		{CallerKey: "main", CalleeKey: "check_value"},
		{CallerKey: "check_value", CalleeKey: "helper"},
		{CallerKey: "check_value", CalleeKey: "logger"},
	}

	// Control dependencies: frontier f1 controls check_value and helper.
	deps := []ControlDependence{
		{FrontierKey: "f1", ControlledBlock: "check_value", Distance: 0},
		{FrontierKey: "f1", ControlledBlock: "helper", Distance: 1},
		{FrontierKey: "f1", ControlledBlock: "logger", Distance: 1},
	}

	builder := NewBuilder(calls, deps, 3)

	// Frontier f1 has edges 100 (true) and 200 (false).
	// Edge 100 is covered, edge 200 is not.
	frontierEdges := map[string][]uint32{
		"f1": {100, 200},
	}
	coverage := bitmap.FromSlice([]uint32{100})

	regions := builder.BuildRegions([]string{"f1"}, coverage, frontierEdges)

	if len(regions) != 1 {
		t.Fatalf("expected 1 region, got %d", len(regions))
	}

	r := regions[0]
	if r.FrontierKey != "f1" {
		t.Errorf("expected frontier f1, got %s", r.FrontierKey)
	}

	// Controlled functions should include check_value, helper, logger.
	expected := map[string]bool{"check_value": true, "helper": true, "logger": true}
	for _, fn := range r.ControlledFunctions {
		if !expected[fn] {
			t.Errorf("unexpected function %s in region", fn)
		}
		delete(expected, fn)
	}
	if len(expected) > 0 {
		t.Errorf("missing functions in region: %v", expected)
	}

	// Uncovered edges should be [200] (100 is covered).
	if len(r.UncoveredEdges) != 1 || r.UncoveredEdges[0] != 200 {
		t.Errorf("expected uncovered=[200], got %v", r.UncoveredEdges)
	}

	t.Logf("Region: frontier=%s, controlled=%v, uncovered=%v",
		r.FrontierKey, r.ControlledFunctions, r.UncoveredEdges)
}

func TestBuildRegionsNoActiveFrontiers(t *testing.T) {
	calls := []CallEdge{
		{CallerKey: "A", CalleeKey: "B"},
	}
	deps := []ControlDependence{
		{FrontierKey: "f1", ControlledBlock: "A", Distance: 0},
	}
	builder := NewBuilder(calls, deps, 3)
	frontierEdges := map[string][]uint32{"f1": {1, 2}}

	regions := builder.BuildRegions(nil, bitmap.EdgeSet{}, frontierEdges)
	if len(regions) != 0 {
		t.Errorf("expected 0 regions with no active frontiers, got %d", len(regions))
	}
	t.Log("No active frontiers → no regions materialized")
}
