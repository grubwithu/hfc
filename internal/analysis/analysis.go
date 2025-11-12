package analysis

import (
	"sort"

	"github.com/google/uuid"
)

var (
	IMPORTANCE_SCORE_THRESHOLD = 0.5
	MAX_CONSTRAINTS            = 10
)
var (
	ALPHA = 0.25
	BETA  = 0.25
	GAMMA = 0.25
	DELTA = 0.25
)

type ImportantConstraint struct {
	CallTreeNode       *CallTreeNode
	HitFrequencyWeight float64
	ComplexityWeight   float64
	UncoveredWeight    float64
	DepthWeight        float64
	ImportanceScore    float64
}

type ConstraintGroup struct {
	GroupId         string  `json:"group_id"`
	MainFunction    string  `json:"function"`
	TotalImportance float64 `json:"importance"`

	Constraints []ImportantConstraint `json:"-"`
}

func GetUncoveredFunctions(callTree *CallTree, coverageMap map[string]int) []*CallTreeNode {
	result := []*CallTreeNode{}

	var filter = func(nodes []*CallTreeNode) []*CallTreeNode {
		var res []*CallTreeNode
		for _, node := range nodes {
			if coverageMap[node.FunctionProfile.FunctionName] > 0 {
				res = append(res, node)
			}
		}
		sort.Slice(res, func(i, j int) bool {
			return coverageMap[res[i].FunctionProfile.FunctionName] < coverageMap[res[j].FunctionProfile.FunctionName]
		})
		return res
	}

	// use bfs to traverse the call tree
	queue := []*CallTreeNode{}
	queue = append(queue, filter(callTree.Root.Children)...)
	for len(queue) > 0 {
		queueCopy := queue
		queue = []*CallTreeNode{}
		for index, node := range queueCopy {
			if index <= len(queue)/3 {
				result = append(result, node)
			} else {
				queue = append(queue, filter(node.Children)...)
			}
		}
	}
	return result
}

func CalculateUncoveredComplexity(ctn *CallTreeNode, coverageMap map[string]int) int {
	res := ctn.FunctionProfile.CyclomaticComplexity
	for _, child := range ctn.Children {
		res += CalculateUncoveredComplexity(child, coverageMap)
	}
	return res
}

func IdentifyImportantConstraints(callTree *CallTree, programCoverageData *ProgramCoverageData) []ImportantConstraint {
	// create a map of function coverage
	coverageMap := make(map[string]int)
	for _, funcCoverage := range programCoverageData.Functions {
		coverageMap[funcCoverage.Name] = funcCoverage.Count
	}

	// get the uncovered functions
	uncoveredFuncs := GetUncoveredFunctions(callTree, coverageMap)

	constraints := []ImportantConstraint{}

	maxComplexity := -1
	maxUncovered := -1
	for _, uncoveredFunc := range uncoveredFuncs {
		hitCount := coverageMap[uncoveredFunc.FunctionProfile.FunctionName]
		hitFreqWeight := 1.0 / (1.0 + float64(hitCount)/float64(programCoverageData.CorpusCount))

		complexity := uncoveredFunc.FunctionProfile.CyclomaticComplexity
		complexityWeight := float64(complexity)
		if complexity > maxComplexity {
			maxComplexity = complexity
		}

		uncoveredComplexity := CalculateUncoveredComplexity(uncoveredFunc, coverageMap)
		uncoveredWeight := float64(uncoveredComplexity)
		if uncoveredComplexity > maxUncovered {
			maxUncovered = uncoveredComplexity
		}

		reachableDepth := uncoveredFunc.GetReachableDepth()
		depthWeight := 1.0 / (1.0 + float64(reachableDepth))

		constraints = append(constraints, ImportantConstraint{
			CallTreeNode:       uncoveredFunc,
			HitFrequencyWeight: hitFreqWeight,
			ComplexityWeight:   complexityWeight,
			UncoveredWeight:    uncoveredWeight,
			DepthWeight:        depthWeight,
		})
	}

	// normalize the weights
	for i := range constraints {
		constraints[i].ComplexityWeight /= float64(maxComplexity)
		constraints[i].UncoveredWeight /= float64(maxUncovered)

		constraints[i].ImportanceScore = ALPHA*constraints[i].HitFrequencyWeight +
			BETA*constraints[i].ComplexityWeight +
			GAMMA*constraints[i].UncoveredWeight +
			DELTA*constraints[i].DepthWeight
	}

	// sort constraints by importance score
	sort.Slice(constraints, func(i, j int) bool {
		return constraints[i].ImportanceScore > constraints[j].ImportanceScore
	})

	cut := MAX_CONSTRAINTS
	if len(constraints) < MAX_CONSTRAINTS {
		cut = len(constraints)
	}

	return constraints[:cut]
}

func GroupConstraintsByFunction(constraints []ImportantConstraint, coverageData *ProgramCoverageData) []ConstraintGroup {
	functionGroups := map[string]*ConstraintGroup{}

	for _, constraint := range constraints {
		funcName := constraint.CallTreeNode.FunctionProfile.FunctionName
		if _, ok := functionGroups[funcName]; !ok {
			functionGroups[funcName] = &ConstraintGroup{
				GroupId:      uuid.New().String(),
				MainFunction: funcName,
			}
		}
		functionGroups[funcName].Constraints = append(functionGroups[funcName].Constraints, constraint)
		functionGroups[funcName].TotalImportance += constraint.ImportanceScore
	}
	result := []ConstraintGroup{}
	for _, group := range functionGroups {
		result = append(result, *group)
	}
	return result
}
