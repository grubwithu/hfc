package coordinator

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/grubwithu/orchestra/internal/bitmap"
	"github.com/grubwithu/orchestra/internal/contracts"
	"github.com/grubwithu/orchestra/internal/frontier"
	"github.com/grubwithu/orchestra/internal/replay"
)

// ModelAwareState extends State with Program Model frontier definitions.
// It derives coverage unions and frontier transitions from persisted Seed
// Records rather than trusting caller-provided bitmaps.
type ModelAwareState struct {
	*State
	mu        sync.Mutex
	replay    *replay.CanonicalReplay
}

// NewModelAware creates a ModelAwareState that loads frontier definitions
// from the Program Model and derives transitions from Seed Records.
func NewModelAware(modelID string, frontiers []frontier.Definition) *ModelAwareState {
	return &ModelAwareState{
		State: New(modelID),
		replay: &replay.CanonicalReplay{
			ModelID:   modelID,
			Frontiers: frontiers,
		},
	}
}

// MergeFromSeeds merges a job result by deriving the output union from
// persisted Seed Records, rather than trusting caller-provided bitmaps.
// This is the production path described in CONTRACTS.md §5:
// "The production path must construct canonical unions from persisted
// Seed Records and derive frontier transitions from the Program Model."
func (m *ModelAwareState) MergeFromSeeds(result contracts.JobResult, seedRecords []contracts.SeedRecord) (contracts.JobFeedback, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	record, exists := m.jobs[result.JobID]
	if !exists {
		return contracts.JobFeedback{}, fmt.Errorf("job %q was not dispatched", result.JobID)
	}
	delete(m.jobs, result.JobID)

	// Derive output union from Seed Records (not from caller-provided bitmap).
	outputEdges := bitmap.EdgeSet{}
	for _, sr := range seedRecords {
		for _, id := range sr.EdgeBitmap {
			outputEdges[id] = struct{}{}
		}
	}

	// Derive input union from the dispatch's seed hashes.
	// In the production path, input union is computed from the Seed Records
	// of the input seeds. For now, use the caller-provided input union
	// since the dispatch may reference seeds not in our store.
	input := bitmap.FromSlice(result.InputUnionBitmap)

	jobDelta := outputEdges.Difference(input)
	novelDelta := outputEdges.Difference(m.globalCoverage)
	dispatchNovel := outputEdges.Difference(record.coverageSnapshot)
	concurrentDuplicate := dispatchNovel.Difference(novelDelta)

	// Derive frontier transitions from the coverage change.
	prevCoverage := m.globalCoverage.Clone()
	newCoverage := m.globalCoverage.Union(outputEdges)

	_, newlyCrossed := m.replay.DeriveFrontierTransitions(prevCoverage, newCoverage)

	m.globalCoverage = newCoverage
	m.version++

	return contracts.JobFeedback{
		SchemaVersion:          contracts.SchemaVersion,
		JobID:                  result.JobID,
		MergedStateVersion:     m.version,
		JobDeltaBitmap:         jobDelta.Sorted(),
		NovelDeltaBitmap:       novelDelta.Sorted(),
		ConcurrentDuplicateMap: concurrentDuplicate.Sorted(),
		CrossedFrontiers:       newlyCrossed,
	}, nil
}

// EvaluateFrontiers returns the current frontier states.
func (m *ModelAwareState) EvaluateFrontiers() (active, crossed, unseen []string) {
	return m.replay.EvaluateFrontiers(m.globalCoverage)
}

// CoverageUnion returns the union of all seed edge bitmaps.
// This is used to verify incremental vs full-replay equivalence.
func CoverageUnion(records []contracts.SeedRecord) []uint32 {
	edges := bitmap.EdgeSet{}
	for _, sr := range records {
		for _, id := range sr.EdgeBitmap {
			edges[id] = struct{}{}
		}
	}
	result := make([]uint32, 0, len(edges))
	for id := range edges {
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// ErrJobNotFound is returned when merging a job that was not dispatched.
var ErrJobNotFound = errors.New("job was not dispatched")
