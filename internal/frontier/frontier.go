// Package frontier evaluates the dynamic state of statically modeled branch
// frontiers. Only exact source-to-runtime mappings are schedulable.
package frontier

import "github.com/grubwithu/orchestra/internal/bitmap"

type State string

const (
	StateIneligible State = "ineligible"
	StateUnseen     State = "unseen"
	StateActive     State = "active"
	StateCrossed    State = "crossed"
)

type Definition struct {
	Key                    string
	MappingStatus          string
	InputDependencyClass   string
	TrueEdgeID             uint32
	FalseEdgeID            uint32
	HasUncoveredDownstream bool
}

type Evaluation struct {
	State              State
	CoveredEdgeID      uint32
	UncoveredEdgeID    uint32
	Evaluated          bool
	PartiallyEvaluated bool
}

func Evaluate(definition Definition, coverage bitmap.EdgeSet) Evaluation {
	if definition.MappingStatus != "exact" ||
		definition.InputDependencyClass == "none" ||
		definition.InputDependencyClass == "unknown" ||
		!definition.HasUncoveredDownstream ||
		definition.TrueEdgeID == definition.FalseEdgeID {
		return Evaluation{State: StateIneligible}
	}
	trueCovered := coverage.Contains(definition.TrueEdgeID)
	falseCovered := coverage.Contains(definition.FalseEdgeID)
	evaluation := Evaluation{
		Evaluated:          trueCovered || falseCovered,
		PartiallyEvaluated: trueCovered != falseCovered,
	}
	switch {
	case trueCovered && falseCovered:
		evaluation.State = StateCrossed
	case trueCovered:
		evaluation.State = StateActive
		evaluation.CoveredEdgeID = definition.TrueEdgeID
		evaluation.UncoveredEdgeID = definition.FalseEdgeID
	case falseCovered:
		evaluation.State = StateActive
		evaluation.CoveredEdgeID = definition.FalseEdgeID
		evaluation.UncoveredEdgeID = definition.TrueEdgeID
	default:
		evaluation.State = StateUnseen
	}
	return evaluation
}
