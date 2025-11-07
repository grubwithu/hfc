package analysis

type CallTreeNode struct {
	FunctionStatic *FunctionStatic
	Count          int
	Children       []*CallTreeNode
	Parent         *CallTreeNode

	CovForwardReds        int
	CovLargestBlockedFunc string
}

type CallTree struct {
	Root  *CallTreeNode
	Nodes map[string]*CallTreeNode
}

func BuildCallTree(staticData *ProgramStaticData) (*CallTree, error) {
	// Preprocess: Traversal all functions and build a map of function name to function static data
	functionMap := make(map[string]*CallTreeNode)
	for _, funcStatic := range staticData.AllFunctions.Elements {
		functionMap[funcStatic.FunctionName] = &CallTreeNode{FunctionStatic: funcStatic}
	}

	// Build the call tree use bfs
	callTree := functionMap["LLVMFuzzerTestOneInput"] // Should be LLVMFuzzerTestOneInput
	queue := []*CallTreeNode{callTree}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, callsite := range cur.FunctionStatic.Callsites {
			if child, ok := functionMap[callsite.Dst]; ok {
				child.Parent = cur
				cur.Children = append(cur.Children, child)
			}
		}
	}

	return &CallTree{Root: callTree, Nodes: functionMap}, nil
}

func (ctn *CallTreeNode) GetDepth() int {
	depth := 0
	for p := ctn.Parent; p != nil; p = p.Parent {
		depth++
	}
	return depth
}

// ApplyCount apply the coverage information to the call tree node
func (ct *CallTree) ApplyCount(programCoverageData *ProgramCoverageData) {
	for _, funcCoverage := range programCoverageData.Functions {
		if node, ok := ct.Nodes[funcCoverage.Name]; ok {
			node.Count = funcCoverage.Count
		}
	}
}

func (ct *CallTree) OverlayWithCoverage(programCoverageData *ProgramCoverageData) {
	ct.ApplyCount(programCoverageData)

	allCallsites := ct.ExtractAllCallsites()
	prev_end := -1
	for idx1, n1 := range allCallsites {
		var prev *CallTreeNode = nil
		if idx1 > 0 {
			prev = allCallsites[idx1-1]
		}
		if n1.Count == 0 && ((prev == nil && prev.GetDepth() <= n1.GetDepth()) || idx1 < prev_end) {
			n1.CovForwardReds = 0
			n1.CovLargestBlockedFunc = "none"
			continue
		}

		// Read forward until we see a green node
		idx2 := idx1 + 1
		forwardRed := 0
		largestBlockedName := ""
		largestBlockedCount := 0
		for idx2 < len(allCallsites) && allCallsites[idx2].Count == 0 {
			n2 := allCallsites[idx2]
			if n2.Count != 0 {
				break
			}
			if n2.FunctionStatic.TotalCyclomaticComplexity > largestBlockedCount {
				largestBlockedName = n2.FunctionStatic.FunctionName
				largestBlockedCount = n2.FunctionStatic.TotalCyclomaticComplexity
			}
			forwardRed++
			idx2++
		}
		n1.CovForwardReds = forwardRed
		n1.CovLargestBlockedFunc = largestBlockedName
		prev_end = idx2 - 1
	}

	// for _, node := range ct.Nodes {
	// 	fmt.Printf("%s find largest blocked func %s\n", node.FunctionStatic.FunctionName, node.CovLargestBlockedFunc)
	// }
}

func (ctn *CallTreeNode) extractAllCallsitesRecursively(result *[]*CallTreeNode) []*CallTreeNode {
	*result = append(*result, ctn)
	for _, child := range ctn.Children {
		child.extractAllCallsitesRecursively(result)
	}
	return *result
}

// ExtractAllCallsites extract all callsites in the call tree by preorder traversal
func (ct *CallTree) ExtractAllCallsites() []*CallTreeNode {
	result := []*CallTreeNode{}
	ct.Root.extractAllCallsitesRecursively(&result)
	return result
}
