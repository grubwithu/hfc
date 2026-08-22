// Package region constructs Regions from the Program Model's call graph,
// control dependence, and dynamic coverage data.
//
// A Region is defined as:
//
//	R = <Frontier F, bounded call context C, controlled subgraph G>
//
// where F is an active frontier, C bounds call context to the last K
// levels, and G is the uncovered-successor-controlled graph after SCC
// compression. Static call/control facts over-approximate; cached dynamic
// function and edge coverage trim the candidate graph. Only active-frontier-
// related Regions are materialized.
package region

import (
	"sort"

	"github.com/grubwithu/orchestra/internal/bitmap"
)

// CallEdge represents a direct call from one function to another.
type CallEdge struct {
	CallerKey string
	CalleeKey string
}

// ControlDependence records which blocks are controlled by a frontier
// and at what distance.
type ControlDependence struct {
	FrontierKey       string
	ControlledBlock   string
	Distance          int
}

// CallGraph is a directed graph of function calls.
type CallGraph struct {
	// adjacency: caller -> set of callees
	edges map[string]map[string]struct{}
	// reverse: callee -> set of callers
	reverse map[string]map[string]struct{}
	// all known functions
	functions map[string]struct{}
}

// NewCallGraph creates a call graph from a list of call edges.
func NewCallGraph(calls []CallEdge) *CallGraph {
	cg := &CallGraph{
		edges:     make(map[string]map[string]struct{}),
		reverse:   make(map[string]map[string]struct{}),
		functions: make(map[string]struct{}),
	}
	for _, c := range calls {
		cg.addEdge(c.CallerKey, c.CalleeKey)
	}
	return cg

}

func (cg *CallGraph) addEdge(caller, callee string) {
	if cg.edges[caller] == nil {
		cg.edges[caller] = make(map[string]struct{})
	}
	cg.edges[caller][callee] = struct{}{}

	if cg.reverse[callee] == nil {
		cg.reverse[callee] = make(map[string]struct{})
	}
	cg.reverse[callee][caller] = struct{}{}

	cg.functions[caller] = struct{}{}
	cg.functions[callee] = struct{}{}
}

// Callees returns the direct callees of a function.
func (cg *CallGraph) Callees(fn string) []string {
	result := make([]string, 0, len(cg.edges[fn]))
	for callee := range cg.edges[fn] {
		result = append(result, callee)
	}
	sort.Strings(result)
	return result
}

// Callers returns the direct callers of a function.
func (cg *CallGraph) Callers(fn string) []string {
	result := make([]string, 0, len(cg.reverse[fn]))
	for caller := range cg.reverse[fn] {
		result = append(result, caller)
	}
	sort.Strings(result)
	return result
}

// Functions returns all known functions.
func (cg *CallGraph) Functions() []string {
	result := make([]string, 0, len(cg.functions))
	for fn := range cg.functions {
		result = append(result, fn)
	}
	sort.Strings(result)
	return result
}

// SCC computes strongly connected components using Tarjan's algorithm.
// Each SCC is a set of function keys. Recursive calls within an SCC
// are collapsed into a single node.
func (cg *CallGraph) SCC() [][]string {
	index := 0
	stack := []string{}
	onStack := make(map[string]bool)
	indices := make(map[string]int)
	lowLinks := make(map[string]int)
	var sccs [][]string

	var strongconnect func(v string)
	strongconnect = func(v string) {
		indices[v] = index
		lowLinks[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		for _, w := range cg.Callees(v) {
			if _, visited := indices[w]; !visited {
				strongconnect(w)
				if lowLinks[w] < lowLinks[v] {
					lowLinks[v] = lowLinks[w]
				}
			} else if onStack[w] {
				if indices[w] < lowLinks[v] {
					lowLinks[v] = indices[w]
				}
			}
		}

		if lowLinks[v] == indices[v] {
			var scc []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			sort.Strings(scc)
			sccs = append(sccs, scc)
		}
	}

	for _, v := range cg.Functions() {
		if _, visited := indices[v]; !visited {
			strongconnect(v)
		}
	}

	sort.Slice(sccs, func(i, j int) bool {
		return sccs[i][0] < sccs[j][0]
	})
	return sccs
}

// Region is a materialized region for an active frontier.
type Region struct {
	FrontierKey   string
	FunctionKey   string
	// ControlledFunctions are the functions in the controlled subgraph
	// after SCC compression and dynamic trimming.
	ControlledFunctions []string
	// UncoveredEdges are the edge IDs in the controlled subgraph that
	// have not yet been covered by any seed.
	UncoveredEdges []uint32
	// CallContextDepth is the bounded call context (K levels).
	CallContextDepth int
}

// Builder constructs Regions from the Program Model and dynamic coverage.
type Builder struct {
	CallGraph     *CallGraph
	Dependencies  []ControlDependence
	MaxContextDepth int
}

// NewBuilder creates a Region builder.
func NewBuilder(calls []CallEdge, deps []ControlDependence, maxContextDepth int) *Builder {
	return &Builder{
		CallGraph:       NewCallGraph(calls),
		Dependencies:   deps,
		MaxContextDepth: maxContextDepth,
	}
}

// BuildRegions constructs Regions for the given active frontiers.
// The coverage parameter is used to trim the controlled subgraph:
// functions whose edges are all covered are excluded.
func (b *Builder) BuildRegions(activeFrontiers []string, coverage bitmap.EdgeSet, frontierEdges map[string][]uint32) []Region {
	// Compute SCCs for the call graph.
	sccs := b.CallGraph.SCC()

	// Build a function-to-SCC mapping.
	funcToSCC := make(map[string]int)
	for i, scc := range sccs {
		for _, fn := range scc {
			funcToSCC[fn] = i
		}
	}

	// Index control dependencies by frontier key.
	depsByFrontier := make(map[string][]ControlDependence)
	for _, dep := range b.Dependencies {
		depsByFrontier[dep.FrontierKey] = append(depsByFrontier[dep.FrontierKey], dep)
	}

	var regions []Region
	for _, frontierKey := range activeFrontiers {
		deps := depsByFrontier[frontierKey]

		// Collect controlled functions (after SCC compression, each
		// controlled function maps to its SCC).
		controlledSCCs := make(map[int]struct{})
		controlledFunctions := make(map[string]struct{})
		for _, dep := range deps {
			controlledFunctions[dep.ControlledBlock] = struct{}{}
			if sccIdx, ok := funcToSCC[dep.ControlledBlock]; ok {
				controlledSCCs[sccIdx] = struct{}{}
			}
		}

		// Expand SCCs to include all functions in the same SCC.
		for sccIdx := range controlledSCCs {
			for _, fn := range sccs[sccIdx] {
				controlledFunctions[fn] = struct{}{}
			}
		}

		// Trim: remove functions whose edges are all covered.
		// (For the first slice, we keep all controlled functions since
		// we don't have per-function edge attribution yet.)
		funcList := make([]string, 0, len(controlledFunctions))
		for fn := range controlledFunctions {
			funcList = append(funcList, fn)
		}
		sort.Strings(funcList)

		// Find uncovered edges for this frontier.
		var uncovered []uint32
		if edges, ok := frontierEdges[frontierKey]; ok {
			for _, edgeID := range edges {
				if !coverage.Contains(edgeID) {
					uncovered = append(uncovered, edgeID)
				}
			}
		}

		regions = append(regions, Region{
			FrontierKey:        frontierKey,
			ControlledFunctions: funcList,
			UncoveredEdges:     uncovered,
			CallContextDepth:   b.MaxContextDepth,
		})
	}

	return regions
}
