// Package probe defines canonical replay independently of any fuzzing engine.
package probe

import (
	"context"
	"time"
)

type Result struct {
	EdgeIDs        []uint32
	FunctionIDs    []uint32
	FrontierIDs    []uint32
	ExecutionTime  time.Duration
	ExitStatus     string
	CrashSignature string
}

type Probe interface {
	Measure(ctx context.Context, seedPath string) (Result, error)
}

type Store interface {
	Has(ctx context.Context, modelID, seedHash string) (bool, error)
	Put(ctx context.Context, modelID, seedHash string, result Result) error
}
