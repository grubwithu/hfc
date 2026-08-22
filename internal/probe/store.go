package probe

import (
	"context"
	"sync"
)

// MemoryStore is an in-memory implementation of Store. It enforces
// at-most-once successful measurement: once a Seed Record is stored,
// subsequent Has() calls return true and Get() returns the cached result.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]map[string]Result // modelID -> seedHash -> Result
}

// NewMemoryStore creates a new in-memory seed store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records: make(map[string]map[string]Result),
	}
}

// Has checks whether a measurement exists for (modelID, seedHash).
func (s *MemoryStore) Has(ctx context.Context, modelID, seedHash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if model, ok := s.records[modelID]; ok {
		_, exists := model[seedHash]
		return exists, nil
	}
	return false, nil
}

// Get returns the cached measurement for (modelID, seedHash).
func (s *MemoryStore) Get(ctx context.Context, modelID, seedHash string) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if model, ok := s.records[modelID]; ok {
		if result, exists := model[seedHash]; exists {
			return result, nil
		}
	}
	return Result{}, ErrNotFound
}

// Put stores a measurement. If a measurement already exists for the same
// (modelID, seedHash), it is NOT overwritten — at-most-once semantics.
func (s *MemoryStore) Put(ctx context.Context, modelID, seedHash string, result Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records[modelID] == nil {
		s.records[modelID] = make(map[string]Result)
	}
	if _, exists := s.records[modelID][seedHash]; exists {
		// At-most-once: do not overwrite.
		return nil
	}
	s.records[modelID][seedHash] = result
	return nil
}

// ErrNotFound is returned when a measurement is not in the store.
var ErrNotFound = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "seed measurement not found" }
