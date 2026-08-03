// Package coordinator implements the minimal deterministic V2 campaign state
// machine. Scheduling policy is intentionally outside this package.
package coordinator

import (
	"errors"
	"fmt"
	"sync"

	"github.com/grubwithu/orchestra/internal/bitmap"
	"github.com/grubwithu/orchestra/internal/contracts"
)

type dispatchedJob struct {
	dispatch         contracts.JobDispatch
	coverageSnapshot bitmap.EdgeSet
}

type State struct {
	mu             sync.Mutex
	modelID        string
	version        uint64
	globalCoverage bitmap.EdgeSet
	jobs           map[string]dispatchedJob
}

func New(modelID string, initialCoverage ...uint32) *State {
	return &State{
		modelID:        modelID,
		globalCoverage: bitmap.FromSlice(initialCoverage),
		jobs:           make(map[string]dispatchedJob),
	}
}

func (s *State) Snapshot() (uint64, []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version, s.globalCoverage.Sorted()
}

func (s *State) Dispatch(job contracts.JobDispatch) (contracts.JobDispatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.JobID == "" {
		return contracts.JobDispatch{}, errors.New("job_id is required")
	}
	if job.ModelID != s.modelID {
		return contracts.JobDispatch{}, fmt.Errorf("job model %q does not match campaign model %q", job.ModelID, s.modelID)
	}
	if _, exists := s.jobs[job.JobID]; exists {
		return contracts.JobDispatch{}, fmt.Errorf("job %q already exists", job.JobID)
	}
	job.SchemaVersion = contracts.SchemaVersion
	job.DispatchStateVersion = s.version
	s.jobs[job.JobID] = dispatchedJob{job, s.globalCoverage.Clone()}
	return job, nil
}

func (s *State) Merge(result contracts.JobResult) (contracts.JobFeedback, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.jobs[result.JobID]
	if !exists {
		return contracts.JobFeedback{}, fmt.Errorf("job %q was not dispatched", result.JobID)
	}
	delete(s.jobs, result.JobID)

	input := bitmap.FromSlice(result.InputUnionBitmap)
	output := bitmap.FromSlice(result.OutputUnionBitmap)
	jobDelta := output.Difference(input)
	novelDelta := output.Difference(s.globalCoverage)
	dispatchNovel := output.Difference(record.coverageSnapshot)
	concurrentDuplicate := dispatchNovel.Difference(novelDelta)

	s.globalCoverage = s.globalCoverage.Union(output)
	s.version++
	return contracts.JobFeedback{
		SchemaVersion:          contracts.SchemaVersion,
		JobID:                  result.JobID,
		MergedStateVersion:     s.version,
		JobDeltaBitmap:         jobDelta.Sorted(),
		NovelDeltaBitmap:       novelDelta.Sorted(),
		ConcurrentDuplicateMap: concurrentDuplicate.Sorted(),
		CrossedFrontiers:       append([]string(nil), result.CrossedFrontiers...),
	}, nil
}
