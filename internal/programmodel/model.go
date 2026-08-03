// Package programmodel defines the immutable semantic/runtime bridge consumed
// by the online coordinator. Loading SQLite and matching CodeQL to LLVM facts
// are separate build-time concerns.
package programmodel

import (
	"errors"
	"fmt"
)

type MappingStatus string

const (
	MappingExact       MappingStatus = "exact"
	MappingAmbiguous   MappingStatus = "ambiguous"
	MappingUnmapped    MappingStatus = "unmapped"
	MappingUnsupported MappingStatus = "unsupported"
)

type RuntimeEdge struct {
	ID               uint32 `json:"edge_id"`
	FunctionKey      string `json:"function_key"`
	File             string `json:"file"`
	Line             int    `json:"line"`
	Column           int    `json:"column"`
	SuccessorOrdinal int    `json:"successor_ordinal"`
	IRFingerprint    string `json:"ir_fingerprint"`
}

type Frontier struct {
	Key                    string        `json:"frontier_key"`
	FunctionKey            string        `json:"function_key"`
	PredicateFingerprint   string        `json:"predicate_fingerprint"`
	PredicateFeatures      []string      `json:"predicate_features"`
	InputDependencyClass   string        `json:"input_dependency_class"`
	TrueEdgeID             *uint32       `json:"true_edge_id,omitempty"`
	FalseEdgeID            *uint32       `json:"false_edge_id,omitempty"`
	MappingStatus          MappingStatus `json:"mapping_status"`
	MappingConfidence      float64       `json:"mapping_confidence"`
	HasUncoveredDownstream bool          `json:"has_uncovered_downstream"`
}

type Model struct {
	ID        string                 `json:"model_id"`
	Edges     map[uint32]RuntimeEdge `json:"runtime_edges"`
	Frontiers map[string]Frontier    `json:"frontiers"`
}

func (model Model) Validate() error {
	var problems []error
	if model.ID == "" {
		problems = append(problems, errors.New("model_id is required"))
	}
	for key, frontier := range model.Frontiers {
		if frontier.Key != key {
			problems = append(problems, fmt.Errorf("frontier map key %q does not match value key %q", key, frontier.Key))
		}
		if frontier.MappingConfidence < 0 || frontier.MappingConfidence > 1 {
			problems = append(problems, fmt.Errorf("frontier %q has invalid confidence", key))
		}
		if frontier.MappingStatus != MappingExact {
			continue
		}
		if frontier.TrueEdgeID == nil || frontier.FalseEdgeID == nil {
			problems = append(problems, fmt.Errorf("exact frontier %q is missing a runtime edge", key))
			continue
		}
		if *frontier.TrueEdgeID == *frontier.FalseEdgeID {
			problems = append(problems, fmt.Errorf("exact frontier %q maps both outcomes to edge %d", key, *frontier.TrueEdgeID))
		}
		for _, edgeID := range []uint32{*frontier.TrueEdgeID, *frontier.FalseEdgeID} {
			if _, exists := model.Edges[edgeID]; !exists {
				problems = append(problems, fmt.Errorf("frontier %q refers to missing edge %d", key, edgeID))
			}
		}
	}
	return errors.Join(problems...)
}
