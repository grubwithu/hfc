// Package bitmap contains the deterministic set operations used by the V2
// contracts. The in-memory representation is intentionally simple; the
// persistence layer can replace it with Roaring Bitmap without changing APIs.
package bitmap

import "sort"

type EdgeSet map[uint32]struct{}

func FromSlice(edges []uint32) EdgeSet {
	result := make(EdgeSet, len(edges))
	for _, edge := range edges {
		result[edge] = struct{}{}
	}
	return result
}

func (s EdgeSet) Clone() EdgeSet {
	result := make(EdgeSet, len(s))
	for edge := range s {
		result[edge] = struct{}{}
	}
	return result
}

func (s EdgeSet) Sorted() []uint32 {
	result := make([]uint32, 0, len(s))
	for edge := range s {
		result = append(result, edge)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (s EdgeSet) Union(other EdgeSet) EdgeSet {
	result := s.Clone()
	for edge := range other {
		result[edge] = struct{}{}
	}
	return result
}

func (s EdgeSet) Difference(other EdgeSet) EdgeSet {
	result := make(EdgeSet)
	for edge := range s {
		if _, exists := other[edge]; !exists {
			result[edge] = struct{}{}
		}
	}
	return result
}

func (s EdgeSet) Contains(edge uint32) bool {
	_, exists := s[edge]
	return exists
}
