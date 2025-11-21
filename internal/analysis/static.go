package analysis

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Define a struct to match the structure of your YAML file
// You'll need to adjust this based on your actual YAML content

type Callsite struct {
	Src string `yaml:"Src"`
	Dst string `yaml:"Dst"`
}

type FunctionProfile struct {
	FunctionName          string     `yaml:"functionName"`
	FunctionSourceFile    string     `yaml:"functionSourceFile"`
	LinkageType           string     `yaml:"linkageType"`
	FunctionLinenumber    int        `yaml:"functionLinenumber"`
	FunctionLinenumberEnd int        `yaml:"functionLinenumberEnd"`
	FunctionDepth         int        `yaml:"functionDepth"`
	ReturnType            string     `yaml:"returnType"`
	ArgCount              int        `yaml:"argCount"`
	ArgTypes              []string   `yaml:"argTypes"`
	ConstantsTouched      []string   `yaml:"constantsTouched"` // Assuming strings, adjust as needed
	ArgNames              []string   `yaml:"argNames"`
	BBCount               int        `yaml:"BBCount"`
	ICount                int        `yaml:"ICount"`
	EdgeCount             int        `yaml:"EdgeCount"`
	CyclomaticComplexity  int        `yaml:"CyclomaticComplexity"`
	FunctionsReached      []string   `yaml:"functionsReached"` // Assuming strings, adjust as needed
	FunctionUses          int        `yaml:"functionUses"`
	BranchProfiles        []string   `yaml:"BranchProfiles"` // Assuming strings, adjust as needed
	Callsites             []Callsite `yaml:"Callsites"`      // Assuming strings, adjust as needed
}

type ProgramProfile struct {
	FuzzerFileName string `yaml:"Fuzzer filename"`
	AllFunctions   struct {
		FunctionListName string             `yaml:"Function list name"`
		Elements         []*FunctionProfile `yaml:"Elements"`
	} `yaml:"All functions"`
}

type CallTreeNode struct {
	FunctionProfile *FunctionProfile
	Children        []*CallTreeNode
	Parent          *CallTreeNode
}

type CallTree struct {
	Root                    *CallTreeNode
	Nodes                   []*CallTreeNode
	MaxDepth                int
	ProgramProfile          *ProgramProfile
	MaxCyclomaticComplexity int
}

func (ctn *CallTreeNode) CountDescendantNode() int {
	// use dfs to count the descendant node
	count := 1
	for _, child := range ctn.Children {
		count += child.CountDescendantNode()
	}
	return count + len(ctn.Children)
}

func (ctn *CallTreeNode) GetMaxLowerDpeth() int {
	// use bfs to get the max depth
	maxDepth := 0
	queue := []*CallTreeNode{ctn}
	for len(queue) > 0 {
		queueCopy := queue
		queue = []*CallTreeNode{}
		for _, node := range queueCopy {
			queue = append(queue, node.Children...)
		}
		maxDepth++
	}
	return maxDepth
}

func (ctn *CallTreeNode) GetUpperDepth() int {
	depth := 0
	cur := ctn.Parent
	for cur != nil {
		depth++
		cur = cur.Parent
	}
	return depth
}

func (ctn *CallTreeNode) GetReachableDepth() int {
	res := ctn.GetUpperDepth()
	res += ctn.GetMaxLowerDpeth()
	return res + 1
}

// func (funcStatic *FunctionStatic) calculateTotalCyclomaticComplexity(functionMap map[string]*FunctionStatic) int {
// 	// Check if the result is already cached
// 	if funcStatic.TotalCyclomaticComplexity != 0 {
// 		return funcStatic.TotalCyclomaticComplexity
// 	}
// 	res := funcStatic.CyclomaticComplexity
// 	for _, funcName := range funcStatic.FunctionsReached {
// 		if funcStatic, ok := functionMap[funcName]; ok {
// 			res += funcStatic.calculateTotalCyclomaticComplexity(functionMap)
// 		}
// 	}
// 	// Cache the result
// 	funcStatic.TotalCyclomaticComplexity = res
// 	return res
// }

// ParseYAMLFile parses a YAML file and returns the parsed data
func ParseProfileFromYAML(filePath string) (*ProgramProfile, error) {
	// Read the YAML file

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %w", err)
	}

	// Parse the YAML data into our struct
	var programProfile ProgramProfile
	err = yaml.Unmarshal(data, &programProfile)
	if err != nil {
		return nil, fmt.Errorf("error parsing YAML file: %w", err)
	}

	var functions map[string]*FunctionProfile = make(map[string]*FunctionProfile)
	for _, funcProfile := range programProfile.AllFunctions.Elements {
		functions[funcProfile.FunctionName] = funcProfile
	}

	// functions["LLVMFuzzerTestOneInput"].calculateTotalCyclomaticComplexity(functions)

	return &programProfile, nil
}

func ParseCallTreeFromData(filePath string, programProfile *ProgramProfile) (*CallTree, error) {
	// Read the data file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading data file: %w", err)
	}

	// split the data by newline
	lines := bytes.Split(data, []byte("\n"))
	if string(lines[0]) != "Call tree" {
		return nil, fmt.Errorf("error parsing calltree file: not start with \"Call tree\"")
	}

	functions := map[string]*FunctionProfile{}
	for _, funcProfile := range programProfile.AllFunctions.Elements {
		functions[funcProfile.FunctionName] = funcProfile
	}

	if strings.Split(string(lines[1]), " ")[0] != "LLVMFuzzerTestOneInput" {
		return nil, fmt.Errorf("error parsing calltree file: root node is not \"LLVMFuzzerTestOneInput\"")
	}

	rootNode := &CallTreeNode{
		FunctionProfile: functions["LLVMFuzzerTestOneInput"],
	}
	nodes := []*CallTreeNode{rootNode}
	callStack := []*CallTreeNode{rootNode}
	maxDepth := len(callStack)
	maxCyclomaticComplexity := 0
	for _, line := range lines[2:] {
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(string(line), "==") {
			break
		}

		prefixSpaceCount := 0
		for line[prefixSpaceCount] == ' ' {
			prefixSpaceCount++
		}

		funcName := strings.Split(string(line[prefixSpaceCount:]), " ")[0]

		node := &CallTreeNode{
			FunctionProfile: functions[funcName],
		}
		nodes = append(nodes, node)
		parent := callStack[prefixSpaceCount/2-1]
		parent.Children = append(parent.Children, node)
		node.Parent = parent
		if prefixSpaceCount/2 >= len(callStack) {
			callStack = append(callStack, node)
		} else {
			callStack[prefixSpaceCount/2] = node
		}
		maxDepth = max(maxDepth, len(callStack))
		maxCyclomaticComplexity = max(maxCyclomaticComplexity, node.FunctionProfile.CyclomaticComplexity)
	}

	return &CallTree{
		Root:                    rootNode,
		Nodes:                   nodes,
		MaxDepth:                maxDepth,
		ProgramProfile:          programProfile,
		MaxCyclomaticComplexity: maxCyclomaticComplexity,
	}, nil

}
