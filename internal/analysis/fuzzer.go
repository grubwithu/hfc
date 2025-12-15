package analysis

import (
	"log"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

type ConstraintType string

const (
	CT_VALUE_COMPARISON     ConstraintType = "val_cmp"  // value comparison
	CT_BITWISE_OPERATION    ConstraintType = "bit_opr"  // bitwise operation
	CT_STRING_MATCH         ConstraintType = "str_mat"  // string match
	CT_ARITHMETIC_OPERATION ConstraintType = "art_opr"  // arithmetic operation
	CT_COMPOUND_OPERATION   ConstraintType = "comp_opr" // compound operation
)

type FuzzerScore map[ConstraintType]float64

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

// analyzeIfClause 分析if语句的条件表达式，确定约束类型
func analyzeIfClause(condition *sitter.Node, sourceCode []byte) ConstraintType {
	if condition == nil {
		return CT_COMPOUND_OPERATION
	}

	conditionCode := condition.Content(sourceCode)

	// 分析条件表达式的内容
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

	if strings.Contains(conditionCode, "&") || strings.Contains(conditionCode, "|") ||
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

func CalculateFuzzerScore(curFileLineCovs []FileLineCov, prevFileLineCovs []FileLineCov, ast map[string]*sitter.Tree) FuzzerScore {
	score := FuzzerScore{
		CT_VALUE_COMPARISON:     0,
		CT_BITWISE_OPERATION:    0,
		CT_STRING_MATCH:         0,
		CT_ARITHMETIC_OPERATION: 0,
		CT_COMPOUND_OPERATION:   0,
	}

	for i := range curFileLineCovs {
		curFileLineCov := &curFileLineCovs[i]
		fileName := curFileLineCov.File

		prevFileLineCov := &prevFileLineCovs[i]
		if prevFileLineCov.File != fileName {
			for i := range prevFileLineCovs {
				if prevFileLineCovs[i].File == fileName {
					prevFileLineCov = &prevFileLineCovs[i]
					break
				}
			}
		}

		log.Println(fileName)

		tree, hasAST := ast[fileName]
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
				statementNode := findStatementAtLine(tree, lineNum)
				if statementNode == nil {
					continue
				}
				// log.Println("find statement at", lineNum, "type", statementNode.Type())
				ifNode := findNearestIfStatement(statementNode)
				if ifNode != nil {
					// log.Println("find an increasing if at", lineNum)
					/*
						if_statments contains:
							if
							parenthesized_expression
							*_statement
							else_clause
						or
							if
							parenthesized_expression
							expression_statement
					*/
					body := findIfBody(ifNode)
					// log.Println(body.StartPoint().Row+1, lineNum, body.EndPoint().Row+1)
					if body.StartPoint().Row+1 <= lineNum && lineNum <= body.EndPoint().Row+1 {
						condition := findIfCondition(ifNode)
						if condition != nil {
							constraintType := analyzeIfClause(condition, prevFileLineCov.GetOriginCode())
							score[constraintType] += 1.0
						}
					}

					index = int(ifNode.EndPoint().Row)
					// log.Println("jump to ", index)
				}
			}
		}
	}

	log.Printf("Fuzzer score calculated: %+v", score)
	return score
}
