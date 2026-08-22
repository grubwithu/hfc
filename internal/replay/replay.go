// Package replay orchestrates canonical seed measurement and frontier
// transition derivation. It is the bridge between the probe (which runs
// seeds against the canonical binary) and the coordinator (which consumes
// coverage to derive job deltas and frontier transitions).
package replay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/grubwithu/orchestra/internal/bitmap"
	"github.com/grubwithu/orchestra/internal/contracts"
	"github.com/grubwithu/orchestra/internal/frontier"
	"github.com/grubwithu/orchestra/internal/probe"
)

// CanonicalReplay measures seeds through the canonical probe, caches results
// in a Seed Store, and derives frontier transitions from the Program Model.
type CanonicalReplay struct {
	ModelID    string
	Probe      probe.Probe
	Store      probe.Store
	Frontiers  []frontier.Definition // exact-mapped frontiers from the Program Model
}

// SeedMeasurement is the result of measuring one seed, including the
// derived frontier transitions.
type SeedMeasurement struct {
	SeedHash        string
	SeedRecord      contracts.SeedRecord
	NewFrontiers    []string // frontier keys that became active
	CrossedFrontiers []string // frontier keys that became crossed
}

// MeasureSeed measures a single seed, using the cached result if available.
// It enforces at-most-once measurement per (modelID, seedHash).
func (r *CanonicalReplay) MeasureSeed(ctx context.Context, seedPath, originFuzzer, originJob string) (SeedMeasurement, error) {
	seedHash, err := hashSeed(seedPath)
	if err != nil {
		return SeedMeasurement{}, fmt.Errorf("hash seed: %w", err)
	}

	// Check if already measured.
	has, err := r.Store.Has(ctx, r.ModelID, seedHash)
	if err != nil {
		return SeedMeasurement{}, fmt.Errorf("check store: %w", err)
	}

	var result probe.Result
	if has {
		result, err = r.Store.Get(ctx, r.ModelID, seedHash)
		if err != nil {
			return SeedMeasurement{}, fmt.Errorf("get from store: %w", err)
		}
	} else {
		// Measure the seed.
		result, err = r.Probe.Measure(ctx, seedPath)
		if err != nil {
			return SeedMeasurement{}, fmt.Errorf("measure seed: %w", err)
		}
		// Persist the measurement.
		if err := r.Store.Put(ctx, r.ModelID, seedHash, result); err != nil {
			return SeedMeasurement{}, fmt.Errorf("store measurement: %w", err)
		}
	}

	// Build the SeedRecord.
	seedSize, _ := os.Stat(seedPath)
	var size int64
	if seedSize != nil {
		size = seedSize.Size()
	}

	record := contracts.SeedRecord{
		SchemaVersion:      contracts.SchemaVersion,
		SeedHash:           seedHash,
		ModelID:            r.ModelID,
		Size:               size,
		OriginFuzzer:       originFuzzer,
		OriginJob:          originJob,
		FirstSeenAt:        time.Now().UTC(),
		ExecutionTimeNanos: result.ExecutionTime.Nanoseconds(),
		EdgeBitmap:         result.EdgeIDs,
		CrashSignature:     result.CrashSignature,
	}

	return SeedMeasurement{
		SeedHash:   seedHash,
		SeedRecord: record,
	}, nil
}

// EvaluateFrontiers evaluates all frontiers against the given coverage set.
// Returns the list of active and crossed frontier keys.
func (r *CanonicalReplay) EvaluateFrontiers(coverage bitmap.EdgeSet) (active, crossed, unseen []string) {
	for _, fdef := range r.Frontiers {
		eval := frontier.Evaluate(fdef, coverage)
		switch eval.State {
		case frontier.StateActive:
			active = append(active, fdef.Key)
		case frontier.StateCrossed:
			crossed = append(crossed, fdef.Key)
		case frontier.StateUnseen:
			unseen = append(unseen, fdef.Key)
		}
	}
	sort.Strings(active)
	sort.Strings(crossed)
	sort.Strings(unseen)
	return
}

// DeriveFrontierTransitions computes which frontiers transitioned from
// the previous coverage state to the new coverage state.
func (r *CanonicalReplay) DeriveFrontierTransitions(prev, curr bitmap.EdgeSet) (newlyActive, newlyCrossed []string) {
	for _, fdef := range r.Frontiers {
		prevEval := frontier.Evaluate(fdef, prev)
		currEval := frontier.Evaluate(fdef, curr)

		// Newly active: was unseen/ineligible, now active.
		if currEval.State == frontier.StateActive && prevEval.State != frontier.StateActive {
			newlyActive = append(newlyActive, fdef.Key)
		}
		// Newly crossed: was not crossed, now crossed.
		if currEval.State == frontier.StateCrossed && prevEval.State != frontier.StateCrossed {
			newlyCrossed = append(newlyCrossed, fdef.Key)
		}
	}
	sort.Strings(newlyActive)
	sort.Strings(newlyCrossed)
	return
}

// hashSeed computes the SHA-256 hash of a seed file.
func hashSeed(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
