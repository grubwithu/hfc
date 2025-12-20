package analysis

import (
	"math"
	"slices"
	"sort"

	"github.com/google/uuid"
)

var (
	IMPORTANCE_SCORE_THRESHOLD = 0.5
	MAX_CONSTRAINTS            = 30
)
var (
	W_HitFreq    = 0.10
	W_Rarity     = 0.20
	W_Depth      = 0.20
	W_Branch     = 0.35
	W_Complexity = 0.15
)

type ImportantConstraint struct {
	CallTreeNode     *CallTreeNode
	HitFreqWeight    float64
	RarityWeight     float64
	DepthWeight      float64
	BranchWeight     float64
	ComplexityWeight float64
	ImportanceScore  float64
}

type ConstraintGroup struct {
	GroupId         string     `json:"group_id"`
	MainFunction    string     `json:"function"`
	FileName        string     `json:"file_name"`
	TotalImportance float64    `json:"importance"`
	Paths           [][]string `json:"paths"`

	Constraints []ImportantConstraint `json:"-"`
}

func IdentifyImportantConstraints(callTree *CallTree, progCovData *ProgCovData) []ImportantConstraint {
	// create a map of function coverage
	MAX_NUM_CHILDREN := len(callTree.Nodes) - 1
	MIN_HITS := math.MaxInt
	MAX_HITS := math.MinInt
	covCdf := CDF{}
	coverageMap := make(map[string]int)
	for _, funcCoverage := range progCovData.Functions {
		coverageMap[funcCoverage.Name] = funcCoverage.Count
		covCdf.Add(float64(funcCoverage.Count))
		if funcCoverage.Count < MIN_HITS {
			MIN_HITS = funcCoverage.Count
		}
		if funcCoverage.Count > MAX_HITS {
			MAX_HITS = funcCoverage.Count
		}
	}

	constraints := []ImportantConstraint{}

	for _, node := range callTree.Nodes {
		if node.FunctionProfile == nil || coverageMap[node.FunctionProfile.FunctionName] == 0 || node == callTree.Root {
			continue
		}
		constraint := ImportantConstraint{
			CallTreeNode: node,
		}
		constraint.HitFreqWeight = (float64(coverageMap[node.FunctionProfile.FunctionName]) - float64(MIN_HITS)) / float64(MAX_HITS-MIN_HITS)
		if constraint.HitFreqWeight >= 0.3 {
			continue
		}
		constraint.HitFreqWeight = constraint.HitFreqWeight / 0.3
		constraint.RarityWeight = 1.0 - covCdf.GetCDFValue(float64(coverageMap[node.FunctionProfile.FunctionName]))
		constraint.DepthWeight = math.Sqrt(float64(node.GetUpperDepth()) / float64(callTree.MaxDepth))
		constraint.BranchWeight = float64(node.CountDescendantNode()) / float64(MAX_NUM_CHILDREN)
		constraint.ComplexityWeight = float64(node.FunctionProfile.CyclomaticComplexity) / float64(callTree.MaxCyclomaticComplexity)
		constraint.ImportanceScore = W_HitFreq*constraint.HitFreqWeight + W_Rarity*constraint.RarityWeight + W_Depth*constraint.DepthWeight + W_Branch*constraint.BranchWeight + W_Complexity*constraint.ComplexityWeight
		constraints = append(constraints, constraint)
	}

	sort.Slice(constraints, func(i, j int) bool {
		return constraints[i].ImportanceScore > constraints[j].ImportanceScore
	})

	cut := MAX_CONSTRAINTS
	if len(constraints) < MAX_CONSTRAINTS {
		cut = len(constraints)
	}

	return constraints[:cut]
}

func GroupConstraintsByFunction(constraints []ImportantConstraint, progCovData *ProgCovData) []ConstraintGroup {
	functionGroups := map[string]*ConstraintGroup{}

	for _, constraint := range constraints {
		funcName := constraint.CallTreeNode.FunctionProfile.FunctionName
		if _, ok := functionGroups[funcName]; !ok {
			functionGroups[funcName] = &ConstraintGroup{
				GroupId:      uuid.New().String(),
				MainFunction: funcName,
				FileName:     constraint.CallTreeNode.FunctionProfile.FunctionSourceFile,
			}
		}
		functionGroups[funcName].Constraints = append(functionGroups[funcName].Constraints, constraint)
		functionGroups[funcName].TotalImportance += constraint.ImportanceScore
	}
	result := []ConstraintGroup{}
	for _, group := range functionGroups {
		for _, constraint := range group.Constraints {
			path := make([]string, 0)
			node := constraint.CallTreeNode.Parent
			for node != nil {
				path = append(path, node.FunctionProfile.FunctionName)
				node = node.Parent
			}
			slices.Reverse(path)
			group.Paths = append(group.Paths, path)
		}
		result = append(result, *group)
	}
	return result
}
