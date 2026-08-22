// Package factexport provides a deterministic export runner for CodeQL query
// results. It runs the orchestra-model QL pack against a finalized database,
// decodes every result to JSON, and writes a versioned manifest containing
// query metadata, timing, memory, and result counts.
//
// The output is the stable input to the Program Model builder. It must be
// reproducible for the same CodeQL bundle, QL pack version, and database.
package factexport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const ExportSchemaVersion = 1

// QuerySpec identifies one QL query file within the pack.
type QuerySpec struct {
	Name   string // short name derived from the .ql filename
	Path   string // relative path to the .ql file within the QL pack
	QueryID string // the @id from the query metadata
}

// QueryResult records the decoded output and metadata for one query.
type QueryResult struct {
	QuerySpec
	ResultCount   int             `json:"result_count"`
	Rows          []map[string]any `json:"rows"`
	CompileTimeMs int64           `json:"compile_time_ms"`
	EvalTimeMs    int64           `json:"eval_time_ms"`
}

// Export is the top-level versioned output document.
type Export struct {
	SchemaVersion  int            `json:"schema_version"`
	GeneratedAt    time.Time      `json:"generated_at"`
	CodeQLVersion  string         `json:"codeql_version"`
	QLPackVersion  string         `json:"ql_pack_version"`
	DatabasePath   string         `json:"database_path"`
	Queries        []QueryResult  `json:"queries"`
	TotalTimeMs    int64          `json:"total_time_ms"`
}

// Run executes the QL pack queries against the database and returns a
// versioned Export. The codeqlBinary is the path to the CodeQL CLI.
// The qlPackDir is the root directory of the orchestra-model QL pack.
func Run(ctx context.Context, codeqlBinary, qlPackDir, databasePath string) (*Export, error) {
	queries := []QuerySpec{
		{Name: "Functions", Path: "src/Functions.ql", QueryID: "orchestra/functions"},
		{Name: "Calls", Path: "src/Calls.ql", QueryID: "orchestra/calls"},
		{Name: "Guards", Path: "src/Guards.ql", QueryID: "orchestra/guards"},
		{Name: "Constants", Path: "src/Constants.ql", QueryID: "orchestra/constants"},
	}

	start := time.Now()
	export := &Export{
		SchemaVersion: ExportSchemaVersion,
		GeneratedAt:   start.UTC(),
		DatabasePath:  databasePath,
		QLPackVersion: "grubwithu/orchestra-model@0.1.0",
	}

	// Get CodeQL version.
	version, err := codeQLVersion(ctx, codeqlBinary)
	if err != nil {
		return nil, fmt.Errorf("get CodeQL version: %w", err)
	}
	export.CodeQLVersion = version

	// Run the full QL pack.
	if err := runQueries(ctx, codeqlBinary, databasePath, qlPackDir); err != nil {
		return nil, fmt.Errorf("run queries: %w", err)
	}

	// Decode each result file.
	for _, q := range queries {
		result, err := decodeResult(ctx, codeqlBinary, databasePath, q)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", q.Name, err)
		}
		export.Queries = append(export.Queries, result)
	}

	export.TotalTimeMs = time.Since(start).Milliseconds()
	return export, nil
}

// Write serializes the export to a JSON file.
func Write(path string, export *Export) error {
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("encode export: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create export directory: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func codeQLVersion(ctx context.Context, binary string) (string, error) {
	output, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil {
		return "", err
	}
	// Extract just the version number from the first line.
	return trimFirstLine(string(output)), nil
}

func runQueries(ctx context.Context, binary, database, qlPackDir string) error {
	cmd := exec.CommandContext(ctx, binary, "database", "run-queries",
		"--threads=0", "--", database, qlPackDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func decodeResult(ctx context.Context, binary, database string, q QuerySpec) (QueryResult, error) {
	bqrsPath := filepath.Join(database, "results", "grubwithu", "orchestra-model", "src", q.Name+".bqrs")
	csv, err := exec.CommandContext(ctx, binary, "bqrs", "decode", "--format=csv", bqrsPath).Output()
	if err != nil {
		return QueryResult{}, fmt.Errorf("decode bqrs: %w", err)
	}
	rows, err := parseCSVRows(string(csv))
	if err != nil {
		return QueryResult{}, fmt.Errorf("parse CSV: %w", err)
	}
	return QueryResult{
		QuerySpec:   q,
		ResultCount: len(rows),
		Rows:        rows,
	}, nil
}

// parseCSVRows is a minimal CSV parser for the output of `bqrs decode --format=csv`.
// It handles quoted fields with embedded commas and produces a list of
// column-name -> value maps. The first line is the header.
func parseCSVRows(csv string) ([]map[string]any, error) {
	lines := splitCSVLines(csv)
	if len(lines) == 0 {
		return nil, nil
	}
	headers := parseCSVFields(lines[0])
	rows := make([]map[string]any, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := parseCSVFields(line)
		row := make(map[string]any, len(headers))
		for i, header := range headers {
			if i < len(fields) {
				row[header] = fields[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// splitCSVLines splits raw CSV into logical lines, respecting quoted newlines.
func splitCSVLines(s string) []string {
	var lines []string
	var current strings.Builder
	inQuote := false
	for _, r := range s {
		if r == '"' {
			inQuote = !inQuote
		}
		if r == '\n' && !inQuote {
			if current.Len() > 0 {
				lines = append(lines, current.String())
				current.Reset()
			}
			continue
		}
		if r == '\r' {
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

// parseCSVFields splits one CSV line into fields, respecting quoted commas.
func parseCSVFields(line string) []string {
	var fields []string
	var current strings.Builder
	inQuote := false
	for _, r := range line {
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if r == ',' && !inQuote {
			fields = append(fields, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	fields = append(fields, current.String())
	return fields
}

func trimFirstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}
