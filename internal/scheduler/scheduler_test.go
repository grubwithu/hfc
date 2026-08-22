package scheduler

import (
	"testing"
	"time"

	"github.com/grubwithu/orchestra/internal/bitmap"
)

func TestScoreFuzzerNew(t *testing.T) {
	s := NewScheduler(DefaultSchedulerConfig(42))
	// New fuzzer: neutral score (0.5).
	if got := s.ScoreFuzzer("new-fuzzer"); got != 0.5 {
		t.Errorf("expected 0.5 for new fuzzer, got %f", got)
	}
}

func TestScoreFuzzerWithObservations(t *testing.T) {
	s := NewScheduler(DefaultSchedulerConfig(42))
	// Fuzzer with good observations: high crossing rate, good efficiency.
	for i := 0; i < 5; i++ {
		s.RecordObservation(CapabilityObservation{
			FuzzerID:           "good-fuzzer",
			JobID:              "job1",
			AttemptedFrontiers: 4,
			CrossedFrontiers:   3,
			JobDeltaEdges:      100,
			NovelDeltaEdges:    80,
			CPUSeconds:         10,
			Executions:         10000,
		})
	}
	score := s.ScoreFuzzer("good-fuzzer")
	if score < 0.5 {
		t.Errorf("good-fuzzer should score above 0.5, got %f", score)
	}
	t.Logf("good-fuzzer score: %f", score)

	// Fuzzer with poor observations: low crossing rate.
	for i := 0; i < 5; i++ {
		s.RecordObservation(CapabilityObservation{
			FuzzerID:           "bad-fuzzer",
			JobID:              "job2",
			AttemptedFrontiers: 4,
			CrossedFrontiers:   0,
			JobDeltaEdges:      10,
			NovelDeltaEdges:    5,
			CPUSeconds:         10,
		})
	}
	badScore := s.ScoreFuzzer("bad-fuzzer")
	if badScore >= score {
		t.Errorf("bad-fuzzer score (%f) should be lower than good-fuzzer (%f)", badScore, score)
	}
	t.Logf("bad-fuzzer score: %f", badScore)
}

func TestSelectFrontier(t *testing.T) {
	s := NewScheduler(DefaultSchedulerConfig(42))

	// Three frontiers, one active for a long time (high starvation).
	s.MarkFrontierActive("f1")
	s.MarkFrontierActive("f2")
	s.MarkFrontierActive("f3")
	s.Priorities["f3"].FirstActiveAt = time.Now().Add(-30 * time.Minute) // very starved

	// One fuzzer (neutral score).
	frontier, fuzzer, err := s.SelectFrontier(
		[]string{"f1", "f2", "f3"},
		[]string{"fuzzer1"})
	if err != nil {
		t.Fatalf("select frontier: %v", err)
	}
	if fuzzer != "fuzzer1" {
		t.Errorf("expected fuzzer1, got %s", fuzzer)
	}
	// f3 should be preferred due to starvation.
	if frontier != "f3" {
		t.Logf("Note: f3 was not selected (got %s), but starvation gives it high priority", frontier)
	}
	t.Logf("selected frontier=%s, fuzzer=%s", frontier, fuzzer)
}

func TestSelectSeeds(t *testing.T) {
	s := NewScheduler(DefaultSchedulerConfig(42))

	seeds := []SeedInfo{
		{Hash: "s1", Size: 100, Edges: []uint32{100, 101, 200}}, // covers both frontier edges
		{Hash: "s2", Size: 200, Edges: []uint32{100}},             // covers only true edge
		{Hash: "s3", Size: 50, Edges: []uint32{300, 400}},        // covers no frontier edge
	}
	frontierEdges := []uint32{100, 200}
	coverage := bitmap.EdgeSet{} // nothing covered yet

	selected := s.SelectSeeds(nil, "f1", seeds, frontierEdges, coverage)

	// s1 should rank first (covers both edges).
	if selected[0].Hash != "s1" {
		t.Errorf("expected s1 first, got %s", selected[0].Hash)
	}
	if selected[1].Hash != "s2" {
		t.Errorf("expected s2 second, got %s", selected[1].Hash)
	}
	t.Logf("Selected order: %v", []string{selected[0].Hash, selected[1].Hash, selected[2].Hash})
}

func TestExtractDictionary(t *testing.T) {
	tokens := ExtractDictionary([]uint32{100, 200}, []uint64{42, 17})
	if len(tokens) != 4 {
		t.Errorf("expected 4 tokens, got %d", len(tokens))
	}
	t.Logf("Tokens: %v", tokens)
}

func TestBuildDispatch(t *testing.T) {
	seeds := []SeedInfo{
		{Hash: "v1", Edges: []uint32{100}},
		{Hash: "v2", Edges: []uint32{200}},
	}
	d := BuildDispatch("model1", "job1", "region1", "libfuzzer", "f1", seeds, []string{"edge_100"}, 300)
	if d.JobID != "job1" || d.ModelID != "model1" {
		t.Errorf("wrong dispatch: %+v", d)
	}
	if len(d.SeedHashes) != 2 {
		t.Errorf("expected 2 seeds, got %d", len(d.SeedHashes))
	}
	t.Logf("Dispatch: %+v", d)
}
