package coordinator

import (
	"reflect"
	"testing"

	"github.com/grubwithu/orchestra/internal/contracts"
)

func TestMergeSeparatesNoveltyFromConcurrentDuplication(t *testing.T) {
	state := New("model-1")
	for _, id := range []string{"job-a", "job-b"} {
		_, err := state.Dispatch(contracts.JobDispatch{JobID: id, ModelID: "model-1"})
		if err != nil {
			t.Fatal(err)
		}
	}

	feedbackA, err := state.Merge(contracts.JobResult{
		JobID: "job-a", InputUnionBitmap: []uint32{1}, OutputUnionBitmap: []uint32{1, 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertEdges(t, "job-a novel", feedbackA.NovelDeltaBitmap, []uint32{1, 2})
	assertEdges(t, "job-a duplicate", feedbackA.ConcurrentDuplicateMap, nil)

	feedbackB, err := state.Merge(contracts.JobResult{
		JobID: "job-b", InputUnionBitmap: []uint32{1}, OutputUnionBitmap: []uint32{1, 2, 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertEdges(t, "job-b local", feedbackB.JobDeltaBitmap, []uint32{2, 3})
	assertEdges(t, "job-b novel", feedbackB.NovelDeltaBitmap, []uint32{3})
	assertEdges(t, "job-b duplicate", feedbackB.ConcurrentDuplicateMap, []uint32{1, 2})

	version, global := state.Snapshot()
	if version != 2 {
		t.Fatalf("version = %d, want 2", version)
	}
	assertEdges(t, "global", global, []uint32{1, 2, 3})
}

func TestDispatchValidatesIdentity(t *testing.T) {
	state := New("model-1")
	if _, err := state.Dispatch(contracts.JobDispatch{JobID: "", ModelID: "model-1"}); err == nil {
		t.Fatal("empty job id unexpectedly accepted")
	}
	if _, err := state.Dispatch(contracts.JobDispatch{JobID: "job", ModelID: "other"}); err == nil {
		t.Fatal("wrong model unexpectedly accepted")
	}
}

func assertEdges(t *testing.T, name string, got, want []uint32) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}
