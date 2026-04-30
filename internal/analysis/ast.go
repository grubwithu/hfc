package analysis

/**
 * All Functions related to AST(sitter) analysis.
 **/

import (
	"log"
	"strings"

	"github.com/gookit/goutil/arrutil"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/cpp"
)

// line is 0-based
func drillDownToLine(node *sitter.Node, targetLine uint32) *sitter.Node {
	if node.StartPoint().Row == targetLine && node.EndPoint().Row == targetLine {
		return node
	}
	cursor := sitter.NewTreeCursor(node)
	defer cursor.Close()

	if cursor.GoToFirstChild() {
		for {
			child := cursor.CurrentNode()
			sRow := child.StartPoint().Row
			eRow := child.EndPoint().Row

			if sRow == targetLine && eRow == targetLine {
				return child
			}

			if sRow <= targetLine && eRow >= targetLine {
				return drillDownToLine(child, targetLine)
			}
			if !cursor.GoToNextSibling() {
				break
			}
		}
	}

	return node
}

// line is 1-based
func findFunctionAtLine(tree *sitter.Tree, line uint32) *sitter.Node {
	if tree == nil || tree.RootNode() == nil {
		return nil
	}

	p := sitter.Point{Row: line - 1, Column: 0}
	root := tree.RootNode()
	node := root.NamedDescendantForPointRange(p, p)

	if node == nil {
		return nil
	}

	targetNode := drillDownToLine(node, line-1)

	current := targetNode
	for current != nil {
		if current.Type() == "function_definition" {
			if current.StartPoint().Row+1 <= line && line <= current.EndPoint().Row+1 {
				return current
			}
		}
		current = current.Parent()
	}

	return nil
}

func getFunctionName(node *sitter.Node, sourceCode []byte) string {
	if node == nil {
		return ""
	}

	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "function_declarator" {
				return getFunctionName(child, sourceCode)
			}
		}
	} else if node.Type() == "function_declarator" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "identifier" {
				return getFunctionName(child, sourceCode)
			}
		}
	} else if node.Type() == "identifier" {
		return node.Content(sourceCode)
	}

	return ""
}

// line is 1-based
func findIfStatementAtLine(tree *sitter.Tree, line uint32) *sitter.Node {
	if tree == nil || tree.RootNode() == nil {
		return nil
	}

	p := sitter.Point{Row: line - 1, Column: 0}
	node := tree.RootNode().NamedDescendantForPointRange(p, p)

	if node == nil {
		return nil
	}

	targetNode := drillDownToLine(node, line-1)

	current := targetNode
	for current != nil {
		if current.Type() == "if_statement" {
			if current.StartPoint().Row+1 <= line && line <= current.EndPoint().Row+1 {
				return current
			}
		}
		current = current.Parent()
	}

	return nil
}

// TODO: use Query to boost the performance
// line is 1-based
func findStatementAtLine(tree *sitter.Tree, targetLine uint32) *sitter.Node {
	if tree == nil || tree.RootNode() == nil {
		return nil
	}

	var foundNode *sitter.Node
	cursor := sitter.NewTreeCursor(tree.RootNode())
	defer cursor.Close()

	for {
		node := cursor.CurrentNode()
		startLine := node.StartPoint().Row + 1 // tree-sitter的行号从0开始

		if startLine == targetLine && node.Type() != "if_statement" && strings.HasSuffix(node.Type(), "_statement") {
			foundNode = node
			break
		}

		if cursor.GoToFirstChild() {
			continue
		}

		if cursor.GoToNextSibling() {
			continue
		}

		for {
			if !cursor.GoToParent() {
				return foundNode
			}
			if cursor.GoToNextSibling() {
				break
			}
		}
	}
	return foundNode
}

func findNearestIfStatement(node *sitter.Node) *sitter.Node {
	if node == nil {
		return nil
	}
	for {
		if node.Type() == "if_statement" {
			return node
		}
		node = node.Parent()
		if node == nil {
			return nil
		}
	}
}

func findIfCondition(node *sitter.Node) *sitter.Node {
	if node.Type() != "if_statement" {
		return nil
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "parenthesized_expression" || child.Type() == "condition_clause" {
			return child
		}
	}
	return nil
}

func findIfBody(node *sitter.Node) *sitter.Node {
	if node.Type() != "if_statement" {
		return nil
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if strings.HasSuffix(child.Type(), "_statement") {
			return child
		}
	}
	return nil
}

// analyzeIfClause
func analyzeIfClause(condition *sitter.Node, sourceCode []byte) ConstraintType {
	if condition == nil {
		return CT_COMPOUND_OPERATION
	}

	conditionCode := condition.Content(sourceCode)

	if strings.Contains(conditionCode, "strcmp") || strings.Contains(conditionCode, "strstr") ||
		strings.Contains(conditionCode, "strncmp") || strings.Contains(conditionCode, "memcmp") ||
		strings.Contains(conditionCode, "\"") || strings.Contains(conditionCode, "'") {
		return CT_STRING_MATCH
	}

	if strings.Contains(conditionCode, "+") || strings.Contains(conditionCode, "-") ||
		strings.Contains(conditionCode, "*") || strings.Contains(conditionCode, "/") ||
		strings.Contains(conditionCode, "%") {
		return CT_ARITHMETIC_OPERATION
	}

	// Check for bitwise operations (excluding logical operators)
	if (strings.Contains(conditionCode, "&") && !strings.Contains(conditionCode, "&&")) ||
		(strings.Contains(conditionCode, "|") && !strings.Contains(conditionCode, "||")) ||
		strings.Contains(conditionCode, "^") || strings.Contains(conditionCode, "~") ||
		strings.Contains(conditionCode, "<<") || strings.Contains(conditionCode, ">>") {
		return CT_BITWISE_OPERATION
	}

	if strings.Contains(conditionCode, "==") || strings.Contains(conditionCode, "!=") ||
		strings.Contains(conditionCode, ">") || strings.Contains(conditionCode, "<") ||
		strings.Contains(conditionCode, ">=") || strings.Contains(conditionCode, "<=") {
		return CT_VALUE_COMPARISON
	}

	return CT_COMPOUND_OPERATION
}

func calculateScore(group ConstraintGroup, input InputGetConstraintGroups) ConstraintScore {
	// Initialize total scores
	totalScores := ConstraintScore{
		CT_VALUE_COMPARISON:     0,
		CT_BITWISE_OPERATION:    0,
		CT_STRING_MATCH:         0,
		CT_ARITHMETIC_OPERATION: 0,
		CT_COMPOUND_OPERATION:   0,
	}

	// Create function profile map for quick lookup
	functionProfileMap := make(map[string]*FunctionProfile)
	for _, profile := range input.FunctionProfiles {
		functionProfileMap[profile.FunctionName] = profile
	}

	// Calculate score for each function in the path
	for i, profile := range group.PathDetail {
		// Check if AST exists for this file
		tree, hasAST := input.AST[profile.FunctionSourceFile]
		if !hasAST {
			continue
		}

		// Find function node
		var funcNode *sitter.Node
		if strings.HasPrefix(profile.FunctionName, "_Z") {
			funcNode = findFunctionAtLine(tree, uint32(profile.FunctionLinenumber))
		} else {
			funcNode = findFunctionByName(tree, input.SourceCode[profile.FunctionSourceFile], profile.FunctionName)
		}

		if funcNode == nil {
			continue
		}

		var lineCov *FileLineCov
		for _, line := range input.LineCovs {
			if line.File == profile.FunctionSourceFile {
				lineCov = &line
				break
			}
		}

		// Analyze function
		scores := analyzeFunction(funcNode, input.SourceCode[profile.FunctionSourceFile], lineCov)

		// Apply weight: closer to leaf = higher weight
		// Weight ranges from 0.5 (root) to 1.5 (leaf)
		weight := 0.5 + (float64(i) / float64(len(group.Path)-1))

		// Add weighted scores to total
		for constraintType, score := range scores {
			totalScores[constraintType] += score * weight
		}
	}

	// Normalize the scores
	maxScore := 0.0
	for _, score := range totalScores {
		if score > maxScore {
			maxScore = score
		}
	}

	if maxScore > 0 {
		for constraintType, score := range totalScores {
			totalScores[constraintType] = score / maxScore
		}
	} else {
		// If all scores are 0, set them to 0 (avoid NaN)
		for constraintType := range totalScores {
			totalScores[constraintType] = 0
		}
	}

	return totalScores
}

type InputCalculateFuzzerScore struct {
	FuzzerName         string
	CurFileLineCovs    []FileLineCov
	PrevFileLineCovs   []FileLineCov
	AST                map[string]*sitter.Tree
	SourceCode         map[string][]byte
	ImportantFunctions []string
}

/**
 * GetFuzzerScore - get fuzzer score from constraint groups.
 *
 * We believe that different fuzzers have varying preferences for different types of constraints.
 * Therefore, we can calculate a preference score for each fuzzer regarding various constraint types.
 **/
func CalculateFuzzerScore(input InputCalculateFuzzerScore) ConstraintScore {
	score := ConstraintScore{
		CT_VALUE_COMPARISON:     0,
		CT_BITWISE_OPERATION:    0,
		CT_STRING_MATCH:         0,
		CT_ARITHMETIC_OPERATION: 0,
		CT_COMPOUND_OPERATION:   0,
	}

	AllIncreaseCount := 0
	ImportantIncreaseCount := 0

	for i := range input.CurFileLineCovs {
		curFileLineCov := &input.CurFileLineCovs[i]
		fileName := curFileLineCov.File

		prevFileLineCov := &input.PrevFileLineCovs[i]
		if prevFileLineCov.File != fileName {
			for i := range input.PrevFileLineCovs {
				if input.PrevFileLineCovs[i].File == fileName {
					prevFileLineCov = &input.PrevFileLineCovs[i]
					break
				}
			}
		}

		// log.Println(fileName)

		tree, hasAST := input.AST[fileName]
		if !hasAST {
			continue
		}

		for index := 0; index < len(curFileLineCov.Lines); index++ {
			curLine := &curFileLineCov.Lines[index]
			lineNum := curLine.LineNumber
			prevLine := &prevFileLineCov.Lines[index]

			if prevLine.LineNumber != lineNum || index+1 != int(lineNum) {
				log.Printf("Warning: Line number %d in file %s does not match", lineNum, fileName)
				break
			}

			prevCount := prevFileLineCov.Lines[index].Count
			curCount := curLine.Count

			if prevCount == 0 && curCount > 0 {
				/*
					statementNode := findStatementAtLine(tree, lineNum)
					if statementNode == nil {
						continue
					}
					// log.Println("find statement at", lineNum, "type", statementNode.Type())
					ifNode := findNearestIfStatement(statementNode)
				*/
				jumpLine := 0
				ifNode := findIfStatementAtLine(tree, lineNum)
				if ifNode != nil {
					// log.Println("find an increasing if at", lineNum)
					/*
						if_statments contains:
							if
							condition_clause
							*_statement
							else_clause
						or
							if
							condition_clause
							expression_statement
					*/
					body := findIfBody(ifNode)
					// fmt.Println(body.StartPoint().Row+1, lineNum, body.EndPoint().Row+1)
					if body != nil && body.StartPoint().Row+1 <= lineNum && lineNum <= body.EndPoint().Row+1 {
						condition := findIfCondition(ifNode)
						if condition != nil {
							constraintType := analyzeIfClause(condition, input.SourceCode[fileName])
							score[constraintType] += 1.0
						}
					}
					jumpLine = int(ifNode.EndPoint().Row) - index
					index = int(ifNode.EndPoint().Row)
					// log.Println("jump to ", index)
				}

				functionName := getFunctionName(findFunctionAtLine(tree, lineNum), input.SourceCode[fileName])
				// log.Println("New line in function ", functionName, " at ", lineNum)

				if arrutil.Contains(input.ImportantFunctions, functionName) {
					ImportantIncreaseCount += jumpLine + 1
				}
				AllIncreaseCount += jumpLine + 1

			}
		}
	}
	log.Println("Fuzzer", input.FuzzerName, "find", AllIncreaseCount, "increases in total,", ImportantIncreaseCount, "of them are important")
	// log.Printf("Fuzzer score calculated: %+v", score)
	return score
}

func findFunctionByName(ast *sitter.Tree, sourceCode []byte, funcName string) *sitter.Node {
	root := ast.RootNode()

	queryStr := `
		(function_definition
			(function_declarator
				(identifier) @target_id
			)
		) @target_def
	`

	q, err := sitter.NewQuery([]byte(queryStr), cpp.GetLanguage())
	if err != nil {
		return nil
	}
	defer q.Close()

	qc := sitter.NewQueryCursor()
	defer qc.Close()

	qc.Exec(q, root)

	for {
		match, ok := qc.NextMatch()
		if !ok {
			break
		}

		var defNode *sitter.Node
		var idName string

		for _, capture := range match.Captures {
			captureName := q.CaptureNameForId(capture.Index)

			switch captureName {
			case "target_id":
				idName = capture.Node.Content(sourceCode)
			case "target_def":
				defNode = capture.Node
			}
		}

		if idName == funcName {
			return defNode
		}
	}

	return nil
}

func analyzeFunction(funcNode *sitter.Node, sourceCode []byte, lineCov *FileLineCov) ConstraintScore {
	if funcNode == nil {
		return ConstraintScore{}
	}

	var maxLineHit uint32
	if lineCov != nil {
		for i := funcNode.StartPoint().Row; i <= funcNode.EndPoint().Row; i++ {
			if lineCov.Lines[i].Count > maxLineHit {
				maxLineHit = lineCov.Lines[i].Count
			}
		}
	}

	queryStr := `(if_statement) @target`

	q, err := sitter.NewQuery([]byte(queryStr), cpp.GetLanguage())
	if err != nil {
		return nil
	}
	defer q.Close()

	qc := sitter.NewQueryCursor()
	defer qc.Close()

	qc.Exec(q, funcNode)

	score := ConstraintScore{}
	for {
		match, ok := qc.NextMatch()
		if !ok {
			break
		}
		for _, capture := range match.Captures {
			if q.CaptureNameForId(capture.Index) == "target" {
				condition := findIfCondition(capture.Node)
				if condition != nil {
					constraintType := analyzeIfClause(condition, sourceCode)

					var scale float64 = 1.0
					// if lineCov != nil {
					// 	var avgHit uint32
					// 	for row := capture.Node.StartPoint().Row; row <= capture.Node.EndPoint().Row; row++ {
					// 		avgHit += lineCov.Lines[row].Count
					// 	}
					// 	avgHit /= capture.Node.EndPoint().Row - capture.Node.StartPoint().Row + 1
					// 	scale = (1 - float64(avgHit)/float64(maxLineHit)) + 0.5 // Range 0.5-1.5, low hit gives higher score
					// }

					score[constraintType] += 1.0 * scale
				}
			}
		}
	}

	// normalize the score
	// maxScore := 0.0
	// for _, v := range score {
	// 	if v > maxScore {
	// 		maxScore = v
	// 	}
	// }
	// for k := range score {
	// 	score[k] /= maxScore
	// }

	return score
}

func ExtractStringLiterals(tree *sitter.Tree, sourceCode []byte, funcName string) []string {
	funcNode := findFunctionByName(tree, sourceCode, funcName)
	if funcNode == nil {
		return nil
	}

	var results []string

	queryStr := `(string_literal (string_content) @content)`
	q, err := sitter.NewQuery([]byte(queryStr), cpp.GetLanguage())
	if err != nil {
		return nil
	}
	defer q.Close()

	qc := sitter.NewQueryCursor()
	defer qc.Close()

	qc.Exec(q, funcNode)

	for {
		match, ok := qc.NextMatch()
		if !ok {
			break
		}

		for _, capture := range match.Captures {
			content := capture.Node.Content(sourceCode)
			if len(content) > 0 {
				results = append(results, content)
			}
		}
	}

	return results
}

// AnalyzeFunctionScore is an exported wrapper for analyzeFunction that finds and analyzes a function by name.
// It returns the constraint scores for the function, or nil if the function cannot be found or analyzed.
func AnalyzeFunctionScore(funcName string, sourceFile string, ast map[string]*sitter.Tree, sourceCode map[string][]byte, lineCovs []FileLineCov) ConstraintScore {
	tree, hasAST := ast[sourceFile]
	if !hasAST {
		log.Printf("AST for file %s not found\n", sourceFile)
		return nil
	}

	// Find function node
	var funcNode *sitter.Node
	if strings.HasPrefix(funcName, "_Z") {
		funcNode = findFunctionAtLine(tree, uint32(0)) // TODO: need line number
	} else {
		funcNode = findFunctionByName(tree, sourceCode[sourceFile], funcName)
	}

	if funcNode == nil {
		return nil
	}

	return analyzeFunction(funcNode, sourceCode[sourceFile], nil)
}
