package frontier

import (
	"testing"

	"github.com/grubwithu/orchestra/internal/bitmap"
)

func TestEvaluateActiveFrontier(t *testing.T) {
	definition := Definition{
		Key: "guard-1", MappingStatus: "exact", InputDependencyClass: "local_direct",
		TrueEdgeID: 10, FalseEdgeID: 11, HasUncoveredDownstream: true,
	}
	evaluation := Evaluate(definition, bitmap.FromSlice([]uint32{10}))
	if evaluation.State != StateActive || !evaluation.PartiallyEvaluated {
		t.Fatalf("evaluation = %#v", evaluation)
	}
	if evaluation.CoveredEdgeID != 10 || evaluation.UncoveredEdgeID != 11 {
		t.Fatalf("edge orientation = %#v", evaluation)
	}
}

func TestEvaluateRejectsAmbiguousOrUnknownFrontier(t *testing.T) {
	tests := []Definition{
		{MappingStatus: "ambiguous", InputDependencyClass: "local_direct", TrueEdgeID: 1, FalseEdgeID: 2, HasUncoveredDownstream: true},
		{MappingStatus: "exact", InputDependencyClass: "unknown", TrueEdgeID: 1, FalseEdgeID: 2, HasUncoveredDownstream: true},
	}
	for _, test := range tests {
		if got := Evaluate(test, bitmap.FromSlice([]uint32{1})); got.State != StateIneligible {
			t.Fatalf("Evaluate(%#v) = %#v", test, got)
		}
	}
}
