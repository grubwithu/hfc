package programmodel

import "testing"

func TestValidateExactFrontier(t *testing.T) {
	trueEdge, falseEdge := uint32(1), uint32(2)
	model := Model{
		ID: "model-1",
		Edges: map[uint32]RuntimeEdge{
			1: {ID: 1, IRFingerprint: "true"},
			2: {ID: 2, IRFingerprint: "false"},
		},
		Frontiers: map[string]Frontier{
			"guard": {
				Key: "guard", MappingStatus: MappingExact, MappingConfidence: 1,
				TrueEdgeID: &trueEdge, FalseEdgeID: &falseEdge,
			},
		},
	}
	if err := model.Validate(); err != nil {
		t.Fatal(err)
	}
	delete(model.Edges, falseEdge)
	if err := model.Validate(); err == nil {
		t.Fatal("missing runtime edge unexpectedly accepted")
	}
}
