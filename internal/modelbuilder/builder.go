// Package modelbuilder merges CodeQL fact exports and LLVM edge manifests
// into an immutable program_model.sqlite database.
//
// The builder reads:
//   - facts.json produced by `orchestra-ossfuzz export-facts`
//   - edge manifest JSON produced by the OrchestraEdgeIDPass LLVM plugin
//   - artifact manifest JSON for provenance
//
// It produces:
//   - program_model.sqlite with functions, calls, runtime_edges, frontiers,
//     and frontier_tokens populated
//
// The mapping algorithm matches CodeQL if-guards to LLVM conditional branch
// edges by file basename and source line. Each match is classified as:
//   - exact: one guard maps to exactly two distinct edge outcomes
//   - ambiguous: multiple plausible mappings remain
//   - unmapped: no runtime relation was found
//   - unsupported: the source/IR construct is outside the supported model
//
// Only exact mappings are schedulable. The builder never guesses.
package modelbuilder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/grubwithu/orchestra/internal/artifact"
	"github.com/grubwithu/orchestra/internal/factexport"
)

// MappingStatus mirrors programmodel.MappingStatus.
type MappingStatus string

const (
	MappingExact       MappingStatus = "exact"
	MappingAmbiguous   MappingStatus = "ambiguous"
	MappingUnmapped    MappingStatus = "unmapped"
	MappingUnsupported MappingStatus = "unsupported"
)

// LLVLEdgeFact is one entry from the LLVM edge manifest JSON.
type LLVMEdgeFact struct {
	EdgeID           uint32   `json:"edge_id"`
	FunctionName     string   `json:"function_name"`
	FunctionLinkage  string   `json:"function_linkage"`
	File             string   `json:"file"`
	Line             int      `json:"line"`
	Column           int      `json:"column"`
	SuccessorOrdinal int      `json:"successor_ordinal"`
	IRFingerprint    string   `json:"ir_fingerprint"`
	InlineStack      []string `json:"inline_stack"`
}

// BuildInput holds all the inputs to the model builder.
type BuildInput struct {
	ModelID       string
	FactsPath     string // path to facts.json
	EdgeManifest  string // path to edge manifest JSON
	ManifestPath  string // path to artifact manifest.json
	SchemaPath    string // path to program_model.sql
	OutputPath    string // path to output program_model.sqlite
}

// Result records the outcome of a model build.
type Result struct {
	ModelID         string
	OutputPath      string
	FunctionCount   int
	CallCount       int
	EdgeCount       int
	FrontierCount   int
	TokenCount      int
	MappingCounts   map[MappingStatus]int
}

// Build creates a program_model.sqlite from CodeQL and LLVM facts.
func Build(input BuildInput) (*Result, error) {
	// Load inputs.
	facts, err := loadFacts(input.FactsPath)
	if err != nil {
		return nil, fmt.Errorf("load facts: %w", err)
	}
	edges, err := loadEdges(input.EdgeManifest)
	if err != nil {
		return nil, fmt.Errorf("load edges: %w", err)
	}
	manifest, err := loadManifest(input.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w", err)
	}

	// Create the output database from the schema.
	if err := createDatabase(input.SchemaPath, input.OutputPath); err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}

	result := &Result{
		ModelID:       input.ModelID,
		OutputPath:    input.OutputPath,
		MappingCounts: make(map[MappingStatus]int),
	}

	// Generate SQL INSERT statements and execute them via sqlite3 CLI.
	var sql strings.Builder
	sql.WriteString("BEGIN TRANSACTION;\n")

	// Insert build provenance.
	insertBuild(&sql, input.ModelID, manifest)

	// Index functions by (qualifiedName, file) to handle duplicate names
	// across different files (common in multi-harness OSS-Fuzz projects).
	functionKeys := make(map[string]string)
	functionRows := extractFunctionRows(facts)
	for _, row := range functionRows {
		fk := functionKey(row)
		name := getString(row, "col1")
		file := getString(row, "col2")
		// Index by both name-only and name+file for call resolution.
		functionKeys[name] = fk
		functionKeys[name+"|"+filepath.Base(file)] = fk
		insertFunction(&sql, fk, row)
		result.FunctionCount++
	}

	// Insert calls. Resolve caller/callee by name, falling back to file context.
	callRows := extractCallRows(facts)
	for _, row := range callRows {
		callerName := getString(row, "col1")
		calleeName := getString(row, "target")
		callerKey := functionKeys[callerName]
		calleeKey := functionKeys[calleeName]
		insertCall(&sql, callerKey, calleeKey, row)
		result.CallCount++
	}

	// Deduplicate edges by edge_id. The same function is compiled multiple
	// times (once per harness that links it), producing duplicate edge facts.
	seenEdges := make(map[uint32]bool)
	uniqueEdges := make([]LLVMEdgeFact, 0, len(edges))
	for _, edge := range edges {
		if seenEdges[edge.EdgeID] {
			continue
		}
		seenEdges[edge.EdgeID] = true
		uniqueEdges = append(uniqueEdges, edge)
	}

	// Insert runtime edges, indexed by (fileBasename, line).
	type edgeIndexKey struct {
		fileBasename string
		line         int
	}
	edgeIndex := make(map[edgeIndexKey][]LLVMEdgeFact)
	for _, edge := range uniqueEdges {
		insertRuntimeEdge(&sql, edge)
		// Resolve function_key from the edge's function name.
		fk := functionKeys[edge.FunctionName]
		if fk == "" {
			fk = edge.FunctionName
		}
		// Update the edge's function reference.
		sql.WriteString(fmt.Sprintf(
			"UPDATE runtime_edges SET function_key='%s' WHERE edge_id=%d;\n",
			escapeSQL(fk), edge.EdgeID))
		result.EdgeCount++

		basename := filepath.Base(edge.File)
		key := edgeIndexKey{basename, edge.Line}
		edgeIndex[key] = append(edgeIndex[key], edge)
	}

	// Process guards as frontiers and attempt mapping.
	guardRows := extractGuardRows(facts)
	constantRows := extractConstantRows(facts)

	// Index constants by (fileBasename, line) for token association.
	constantsByLoc := make(map[edgeIndexKey][]map[string]any)
	for _, row := range constantRows {
		basename := filepath.Base(getString(row, "col2"))
		line := getInt(row, "col3")
		key := edgeIndexKey{basename, line}
		constantsByLoc[key] = append(constantsByLoc[key], row)
	}

	for _, row := range guardRows {
		fk := functionKeys[getString(row, "col1")]
		if fk == "" {
			fk = getString(row, "col1")
		}
		guardFile := getString(row, "col2")
		guardLine := getInt(row, "col3")
		basename := filepath.Base(guardFile)

		// Find candidate edges at this file+line.
		key := edgeIndexKey{basename, guardLine}
		candidates := edgeIndex[key]

		frontierKey := frontierKey(row, input.ModelID)
		status, trueEdge, falseEdge := classifyMapping(candidates)

		// Determine input dependency (unknown for now; T2.5 will refine).
		inputDep := "unknown"

		insertFrontier(&sql, frontierKey, fk, row, inputDep,
			status, trueEdge, falseEdge)
		result.FrontierCount++
		result.MappingCounts[status]++

		// Associate constants as frontier tokens.
		for _, constRow := range constantsByLoc[key] {
			insertFrontierToken(&sql, frontierKey, constRow)
			result.TokenCount++
		}
	}

	sql.WriteString("COMMIT;\n")

	// Execute the SQL via sqlite3 CLI.
	if err := executeSQL(input.OutputPath, sql.String()); err != nil {
		return nil, fmt.Errorf("execute SQL: %w", err)
	}

	return result, nil
}

// loadFacts reads and parses the facts.json export.
func loadFacts(path string) (*factexport.Export, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var export factexport.Export
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, err
	}
	return &export, nil
}

// loadEdges reads and parses the LLVM edge manifest. The pass writes in
// JSON Lines format (one JSON object per line) because Clang invokes
// the pass once per translation unit.
func loadEdges(path string) ([]LLVMEdgeFact, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var edges []LLVMEdgeFact
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var edge LLVMEdgeFact
		if err := json.Unmarshal([]byte(line), &edge); err != nil {
			return nil, fmt.Errorf("parse edge line %q: %w", line, err)
		}
		edges = append(edges, edge)
	}
	return edges, nil
}

// loadManifest reads and parses the artifact manifest.json.
func loadManifest(path string) (*artifact.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m artifact.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// createDatabase creates a fresh SQLite database from the schema file.
func createDatabase(schemaPath, outputPath string) error {
	// Remove existing database.
	if err := os.Remove(outputPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove existing database: %w", err)
	}
	// Execute the schema via sqlite3 CLI.
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	return executeSQL(outputPath, string(schema))
}

// executeSQL executes SQL via the sqlite3 CLI by piping SQL text to stdin.
func executeSQL(dbPath, sqlText string) error {
	cmd := exec.Command("sqlite3", dbPath)
	cmd.Stdin = strings.NewReader(sqlText)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sqlite3: %w\n%s", err, string(output))
	}
	return nil
}

// execCommand is a helper that runs a command and returns an error on failure.
func execCommand(name string, args ...string) error {
	return execCommandContext(nil, name, args...)
}

// classifyMapping determines the mapping status for a guard given candidate edges.
func classifyMapping(candidates []LLVMEdgeFact) (MappingStatus, *uint32, *uint32) {
	if len(candidates) == 0 {
		return MappingUnmapped, nil, nil
	}
	if len(candidates) == 1 {
		// Only one edge found — can't form a true/false pair.
		return MappingAmbiguous, nil, nil
	}

	// Group edges by successor ordinal.
	// We expect exactly two edges: ordinal 0 (true) and ordinal 1 (false).
	var trueEdge, falseEdge *LLVMEdgeFact
	for i := range candidates {
		e := &candidates[i]
		if e.SuccessorOrdinal == 0 {
			if trueEdge != nil {
				// Multiple edges for the same ordinal — ambiguous.
				return MappingAmbiguous, nil, nil
			}
			trueEdge = e
		} else if e.SuccessorOrdinal == 1 {
			if falseEdge != nil {
				return MappingAmbiguous, nil, nil
			}
			falseEdge = e
		}
	}

	if trueEdge != nil && falseEdge != nil {
		if trueEdge.EdgeID == falseEdge.EdgeID {
			return MappingUnsupported, nil, nil
		}
		tid := trueEdge.EdgeID
		fid := falseEdge.EdgeID
		return MappingExact, &tid, &fid
	}

	// Edges exist but don't form a clean true/false pair.
	return MappingAmbiguous, nil, nil
}

// --- Key generation ---

func functionKey(row map[string]any) string {
	name := getString(row, "col1")
	file := getString(row, "col2")
	line := getInt(row, "col3")
	col := getInt(row, "col4")
	data := fmt.Sprintf("%s|%s|%d:%d", name, file, line, col)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

func frontierKey(row map[string]any, modelID string) string {
	file := getString(row, "col2")
	line := getInt(row, "col3")
	col := getInt(row, "col4")
	predicate := getString(row, "col7")
	data := fmt.Sprintf("%s|%s|%d:%d|%s", modelID, file, line, col, predicate)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// --- SQL generation ---

func insertBuild(sql *strings.Builder, modelID string, m *artifact.Manifest) {
	buildCommandHash := m.BuildFingerprint
	fmt.Fprintf(sql,
		"INSERT INTO builds (model_id, source_commit, source_tree_hash, oss_fuzz_commit, oss_fuzz_project, build_profile, project_definition_hash, build_command_hash, compiler_version, codeql_version, ql_pack_version, llvm_pass_version, schema_version) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 1);\n",
		escapeSQL(modelID),
		escapeSQL(m.SourceRevision),
		escapeSQL(m.SourceTreeHash),
		escapeSQL(m.OSSFuzzRevision),
		escapeSQL(m.OSSFuzzProject),
		escapeSQL(m.Profile),
		escapeSQL(m.ProjectDefinitionHash),
		escapeSQL(buildCommandHash),
		escapeSQL(m.CompilerVersion),
		escapeSQL(m.CodeQLVersion),
		escapeSQL(m.QLPackVersion),
		escapeSQL(m.LLVMPassVersion),
	)
}

func insertFunction(sql *strings.Builder, fk string, row map[string]any) {
	fmt.Fprintf(sql,
		"INSERT OR IGNORE INTO functions (function_key, qualified_name, file, start_line, start_column, end_line, end_column, linkage, cyclomatic_complexity, reachable_from_harness) VALUES ('%s', '%s', '%s', %d, %d, %d, %d, '%s', NULL, %d);\n",
		escapeSQL(fk),
		escapeSQL(getString(row, "col1")),
		escapeSQL(getString(row, "col2")),
		getInt(row, "col3"),
		getInt(row, "col4"),
		getInt(row, "col5"),
		getInt(row, "col6"),
		escapeSQL(linkageString(row)),
		getInt(row, "col8"),
	)
}

func insertCall(sql *strings.Builder, callerKey, calleeKey string, row map[string]any) {
	if callerKey == "" {
		callerKey = getString(row, "col1")
	}
	if calleeKey == "" {
		calleeKey = getString(row, "target")
	}
	ck := callerKey + "|" + calleeKey + "|" +
		fmt.Sprintf("%d:%d", getInt(row, "col4"), getInt(row, "col5"))
	hash := sha256.Sum256([]byte(ck))
	callsiteKey := hex.EncodeToString(hash[:16])

	confidence := 1.0
	fmt.Fprintf(sql,
		"INSERT OR IGNORE INTO calls (callsite_key, caller_key, callee_key, file, line, column, dispatch_kind, confidence) VALUES ('%s', '%s', '%s', '%s', %d, %d, 'direct', %g);\n",
		escapeSQL(callsiteKey),
		escapeSQL(callerKey),
		escapeSQL(calleeKey),
		escapeSQL(getString(row, "col3")),
		getInt(row, "col4"),
		getInt(row, "col5"),
		confidence,
	)
}

func insertRuntimeEdge(sql *strings.Builder, edge LLVMEdgeFact) {
	fmt.Fprintf(sql,
		"INSERT OR IGNORE INTO runtime_edges (edge_id, function_key, file, line, column, successor_ordinal, ir_fingerprint) VALUES (%d, '%s', '%s', %d, %d, %d, '%s');\n",
		edge.EdgeID,
		escapeSQL(edge.FunctionName),
		escapeSQL(edge.File),
		edge.Line,
		edge.Column,
		edge.SuccessorOrdinal,
		escapeSQL(edge.IRFingerprint),
	)
}

func insertFrontier(sql *strings.Builder, fk, funcKey string, row map[string]any, inputDep string, status MappingStatus, trueEdge, falseEdge *uint32) {
	predicate := getString(row, "col7")
	predicateFP := hashString(predicate)
	predTypeVector := fmt.Sprintf(`{"operator":"%s","type":"%s","has_constant":%d}`,
		getString(row, "col9"), getString(row, "col8"), getInt(row, "col10"))

	trueStr := "NULL"
	falseStr := "NULL"
	if trueEdge != nil {
		trueStr = fmt.Sprintf("%d", *trueEdge)
	}
	if falseEdge != nil {
		falseStr = fmt.Sprintf("%d", *falseEdge)
	}

	fmt.Fprintf(sql,
		"INSERT OR IGNORE INTO frontiers (frontier_key, function_key, file, line, column, predicate_fingerprint, predicate_type_vector_json, input_dependency_class, true_edge_id, false_edge_id, mapping_status, mapping_confidence) VALUES ('%s', '%s', '%s', %d, %d, '%s', '%s', '%s', %s, %s, '%s', %g);\n",
		escapeSQL(fk),
		escapeSQL(funcKey),
		escapeSQL(getString(row, "col2")),
		getInt(row, "col3"),
		getInt(row, "col4"),
		escapeSQL(predicateFP),
		escapeSQL(predTypeVector),
		escapeSQL(inputDep),
		trueStr,
		falseStr,
		escapeSQL(string(status)),
		1.0,
	)
}

func insertFrontierToken(sql *strings.Builder, frontierKey string, row map[string]any) {
	value := getString(row, "col6")
	tokenKind := "integer"
	if strings.Contains(value, "\"") || strings.Contains(value, "'") {
		tokenKind = "string"
	}
	fmt.Fprintf(sql,
		"INSERT OR IGNORE INTO frontier_tokens (frontier_key, token_kind, token_value, source_kind, confidence) VALUES ('%s', '%s', '%s', 'predicate_constant', 1.0);\n",
		escapeSQL(frontierKey),
		tokenKind,
		escapeSQL(value),
	)
}

// --- Helpers ---

func loadFactsRows(facts *factexport.Export, name string) []map[string]any {
	for _, q := range facts.Queries {
		if q.Name == name {
			return q.Rows
		}
	}
	return nil
}

func extractFunctionRows(facts *factexport.Export) []map[string]any {
	return loadFactsRows(facts, "Functions")
}

func extractCallRows(facts *factexport.Export) []map[string]any {
	return loadFactsRows(facts, "Calls")
}

func extractGuardRows(facts *factexport.Export) []map[string]any {
	return loadFactsRows(facts, "Guards")
}

func extractConstantRows(facts *factexport.Export) []map[string]any {
	return loadFactsRows(facts, "Constants")
}

func getString(row map[string]any, key string) string {
	if v, ok := row[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func getInt(row map[string]any, key string) int {
	if v, ok := row[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		case string:
			var i int
			fmt.Sscanf(n, "%d", &i)
			return i
		}
	}
	return 0
}

func linkageString(row map[string]any) string {
	v := getInt(row, "col8")
	if v == 1 {
		return "external"
	}
	return "internal"
}

func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:16])
}

func escapeSQL(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// execCommandContext is split to avoid importing context in this file.
// The actual implementation is in exec.go.
func execCommandContext(ctx interface{}, name string, args ...string) error {
	return execSQLViaCLI(name, args...)
}

var _ = execCommandContext // retain for future use
