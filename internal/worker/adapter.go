// Package worker defines the engine-neutral boundary around fuzzer processes.
package worker

import (
	"context"

	"github.com/grubwithu/orchestra/internal/contracts"
)

type Candidate struct {
	Path       string
	SeedHash   string
	ParentHash string
	Crash      bool
}

type RunResult struct {
	Job        contracts.JobResult
	Candidates []Candidate
}

type Adapter interface {
	ID() string
	Run(ctx context.Context, dispatch contracts.JobDispatch) (RunResult, error)
}
