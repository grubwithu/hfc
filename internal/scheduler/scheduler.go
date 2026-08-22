// Package scheduler implements seed selection, capability observation,
// and job dispatch policy. The first slice uses an explainable linear
// policy with deterministic inputs (RNG seed) so decisions can be replayed.
package scheduler

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/grubwithu/orchestra/internal/bitmap"
	"github.com/grubwithu/orchestra/internal/contracts"
	"github.com/grubwithu/orchestra/internal/region"
)

// CapabilityObservation is the evidence-backed record of one fuzzer's
// progress across a set of Regions.
type CapabilityObservation struct {
	FuzzerID              string
	JobID                 string
	AttemptedFrontiers    int
	CrossedFrontiers      int
	JobDeltaEdges         int
	NovelDeltaEdges       int
	CPUSeconds            float64
	Executions            int
	ReplayOverheadSeconds float64
	ObservedAt            time.Time
}

// Observation = edges that became crossed in this job
func (o CapabilityObservation) CrossingRate() float64 {
	if o.AttemptedFrontiers == 0 {
		return 0
	}
	return float64(o.CrossedFrontiers) / float64(o.AttemptedFrontiers)
}

// CoverageEfficiency = novel edges per CPU second.
func (o CapabilityObservation) CoverageEfficiency() float64 {
	if o.CPUSeconds == 0 {
		return 0
	}
	return float64(o.NovelDeltaEdges) / o.CPUSeconds
}

// SchedulerConfig configures the linear policy weights.
type SchedulerConfig struct {
	// Weight for frontier-crossing rate (higher = prefer fuzzers that cross frontiers).
	WeightCrossingRate float64
	// Weight for coverage efficiency (higher = prefer fuzzers that cover edges per CPU second).
	WeightEfficiency float64
	// Weight for time-budget fairness (higher = prefer starved frontiers).
	WeightStarvation float64
	// Number of seeds to attach per dispatch.
	SeedBatchSize int
	// Time budget per dispatch, in seconds.
	DefaultTimeBudgetSeconds int64
	// RNG seed for deterministic replay.
	RNGSeed int64
}

// DefaultSchedulerConfig returns the recommended weights for a first slice.
func DefaultSchedulerConfig(rngSeed int64) SchedulerConfig {
	return SchedulerConfig{
		WeightCrossingRate:       1.0,
		WeightEfficiency:          1.0,
		WeightStarvation:          0.1,
		SeedBatchSize:            16,
		DefaultTimeBudgetSeconds: 300,
		RNGSeed:                   rngSeed,
	}
}

// FrontierPriority tracks how long a frontier has been waiting for dispatch.
type FrontierPriority struct {
	FrontierKey  string
	FirstActiveAt time.Time
	LastDispatchedAt time.Time
	// Average fuzzer score for this frontier (from recent observations).
	AvgFuzzerScore float64
}

// Scheduler selects seeds and constructs job dispatches for active frontiers.
type Scheduler struct {
	Cfg          SchedulerConfig
	RNG          *rand.Rand
	Observations map[string][]CapabilityObservation // fuzzerID -> recent observations
	Priorities   map[string]*FrontierPriority       // frontierKey -> priority
}

// NewScheduler creates a scheduler with the given config.
func NewScheduler(cfg SchedulerConfig) *Scheduler {
	return &Scheduler{
		Cfg:          cfg,
		RNG:          rand.New(rand.NewSource(cfg.RNGSeed)),
		Observations: make(map[string][]CapabilityObservation),
		Priorities:   make(map[string]*FrontierPriority),
	}
}

// RecordObservation appends a capability observation for a fuzzer.
func (s *Scheduler) RecordObservation(obs CapabilityObservation) {
	s.Observations[obs.FuzzerID] = append(s.Observations[obs.FuzzerID], obs)
	// Keep only the most recent 32 observations per fuzzer.
	if len(s.Observations[obs.FuzzerID]) > 32 {
		s.Observations[obs.FuzzerID] = s.Observations[obs.FuzzerID][len(s.Observations[obs.FuzzerID])-32:]
	}
}

// ScoreFuzzer returns the linear-policy score for a fuzzer.
func (s *Scheduler) ScoreFuzzer(fuzzerID string) float64 {
	obs := s.Observations[fuzzerID]
	if len(obs) == 0 {
		return 0.5 // prior: neutral score for new fuzzers
	}
	// Compute average metrics over recent observations.
	var crossingSum, effSum float64
	for _, o := range obs {
		crossingSum += o.CrossingRate()
		effSum += o.CoverageEfficiency()
	}
	avgCrossing := crossingSum / float64(len(obs))
	avgEff := effSum / float64(len(obs))
	// Normalize efficiency (typical: 0.1-1000 edges/sec).
	normEff := math.Tanh(avgEff / 100.0)
	return s.Cfg.WeightCrossingRate*avgCrossing + s.Cfg.WeightEfficiency*normEff
}

// MarkFrontierActive registers a frontier as active at the current time.
func (s *Scheduler) MarkFrontierActive(frontierKey string) {
	now := time.Now()
	if p, ok := s.Priorities[frontierKey]; ok {
		p.FirstActiveAt = now
	} else {
		s.Priorities[frontierKey] = &FrontierPriority{
			FrontierKey:   frontierKey,
			FirstActiveAt: now,
		}
	}
}

// StarvationScore returns a score that grows with time since a frontier's
// last dispatch.
func (s *Scheduler) StarvationScore(frontierKey string) float64 {
	p, ok := s.Priorities[frontierKey]
	if !ok {
		return 0
	}
	reference := p.FirstActiveAt
	if !p.LastDispatchedAt.IsZero() {
		reference = p.LastDispatchedAt
	}
	elapsed := time.Since(reference).Seconds()
	// Normalize to [0, 1] with a 10-minute saturation.
	return math.Min(elapsed/600.0, 1.0)
}

// SelectFrontier picks the next frontier to dispatch, combining frontier
// crossing potential, fuzzer score, and starvation. Returns nil if no
// frontier is eligible.
func (s *Scheduler) SelectFrontier(activeFrontiers []string, availableFuzzers []string) (string, string, error) {
	if len(activeFrontiers) == 0 || len(availableFuzzers) == 0 {
		return "", "", fmt.Errorf("no active frontiers or fuzzers available")
	}

	// Compute average fuzzer score.
	var fuzzerScoreSum float64
	for _, f := range availableFuzzers {
		fuzzerScoreSum += s.ScoreFuzzer(f)
	}
	avgFuzzerScore := fuzzerScoreSum / float64(len(availableFuzzers))

	type candidate struct {
		frontier string
		fuzzer   string
		score    float64
	}
	var candidates []candidate
	for _, fk := range activeFrontiers {
		p := s.Priorities[fk]
		if p == nil {
			continue
		}
		fuzzScore := avgFuzzerScore
		starv := s.StarvationScore(fk)
		score := fuzzScore + s.Cfg.WeightStarvation*starv
		candidates = append(candidates, candidate{fk, availableFuzzers[0], score})
	}
	if len(candidates) == 0 {
		return "", "", fmt.Errorf("no eligible frontier/fuzzer pair")
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	best := candidates[0]
	// Add jitter for exploration.
	if len(candidates) > 1 && s.RNG.Float64() < 0.2 {
		best = candidates[1+s.RNG.Intn(len(candidates)-1)]
	}

	best.fuzzer = availableFuzzers[0]
	if s.Priorities[best.frontier] != nil {
		s.Priorities[best.frontier].LastDispatchedAt = time.Now()
	}
	return best.frontier, best.fuzzer, nil
}

// SelectSeeds picks seeds from the available pool for a frontier. The first
// slice uses frontier-edge overlap as the score: seeds that cover edges
// closer to the frontier's uncovered side are preferred.
func (s *Scheduler) SelectSeeds(ctx context.Context, frontierKey string, available []SeedInfo, frontierEdges []uint32, covered bitmap.EdgeSet) []SeedInfo {
	if len(available) == 0 {
		return nil
	}
	type scored struct {
		seed  SeedInfo
		score float64
	}
	var candidates []scored
	for _, seed := range available {
		// Score: count of frontier edges that the seed covers that are
		// currently uncovered globally.
		var score float64
		for _, e := range seed.Edges {
			for _, fe := range frontierEdges {
				if e == fe && !covered.Contains(e) {
					score += 1.0
				}
			}
		}
		// Add small random jitter for diversity.
		score += s.RNG.Float64() * 0.1
		// Smaller seeds are slightly preferred (faster replay).
		score -= float64(seed.Size) / 1e9
		candidates = append(candidates, scored{seed, score})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	n := s.Cfg.SeedBatchSize
	if n > len(candidates) {
		n = len(candidates)
	}
	result := make([]SeedInfo, 0, n)
	for i := 0; i < n; i++ {
		result = append(result, candidates[i].seed)
	}
	return result
}

// SeedInfo is the minimum information needed to select a seed.
type SeedInfo struct {
	Hash  string
	Size  int64
	Edges []uint32
}

// ExtractDictionary returns predicate-derived dictionary tokens for a frontier.
// This is a simple first-slice implementation that returns edge IDs as
// token candidates; production would mine integer/string constants from
// the Program Model's frontier_tokens table.
func ExtractDictionary(frontierEdges []uint32, constants []uint64) []string {
	tokens := make([]string, 0, len(frontierEdges)+len(constants))
	for _, e := range frontierEdges {
		tokens = append(tokens, fmt.Sprintf("edge_%d", e))
	}
	for _, c := range constants {
		tokens = append(tokens, fmt.Sprintf("const_%d", c))
	}
	sort.Strings(tokens)
	return tokens
}

// BuildDispatch constructs a JobDispatch from a selected frontier and seeds.
func BuildDispatch(modelID, jobID, regionID, fuzzerID, frontierKey string, seeds []SeedInfo, dictionary []string, timeBudgetSeconds int64) contracts.JobDispatch {
	seedHashes := make([]string, len(seeds))
	for i, s := range seeds {
		seedHashes[i] = s.Hash
	}
	return contracts.JobDispatch{
		JobID:             jobID,
		ModelID:           modelID,
		RegionID:          regionID,
		FrontierIDs:       []string{frontierKey},
		FuzzerID:          fuzzerID,
		SeedHashes:        seedHashes,
		DictionaryTokens:  dictionary,
		TimeBudgetSeconds: timeBudgetSeconds,
	}
}

// AssignRegionToFrontier maps a frontier to its corresponding Region.
func AssignRegionToFrontier(regions []region.Region) map[string]region.Region {
	out := make(map[string]region.Region, len(regions))
	for _, r := range regions {
		out[r.FrontierKey] = r
	}
	return out
}
