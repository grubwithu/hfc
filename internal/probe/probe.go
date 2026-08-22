// Package probe defines canonical replay independently of any fuzzing engine.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Result holds the canonical measurement of one seed.
type Result struct {
	EdgeIDs        []uint32
	FunctionIDs    []uint32
	FrontierIDs    []uint32
	ExecutionTime  time.Duration
	ExitStatus     string
	CrashSignature string
}

// Probe measures seeds against a canonical binary via subprocess execution.
type Probe interface {
	Measure(ctx context.Context, seedPath string) (Result, error)
}

// Store persists canonical measurements keyed by (model_id, seed_hash).
type Store interface {
	Has(ctx context.Context, modelID, seedHash string) (bool, error)
	Get(ctx context.Context, modelID, seedHash string) (Result, error)
	Put(ctx context.Context, modelID, seedHash string, result Result) error
}

// SubprocessProbe runs a fuzzer binary in replay mode (single seed, no fuzzing)
// and captures edge coverage from the Orchestra edge runtime output.
//
// The binary must be built with -fpass-plugin=OrchestraEdgeIDPass.so and
// linked with liborchestra_edge_runtime.a (or use the weak no-op fallback).
// Coverage is dumped to a file via ORCHESTRA_COVERAGE_OUT.
//
// Since the fuzzer binary may require a different GLIBC than the host, the
// probe runs it inside a Docker container using the base-runner image.
type SubprocessProbe struct {
	ModelID       string
	BinaryPath    string // path to the fuzzer binary on the host
	BinaryName    string // name of the binary inside the container
	DockerImage   string // Docker image to use (e.g. base-runner)
	CoverageDir   string // temp directory for coverage output
	DockerBinary  string // path to docker executable
}

// NewSubprocessProbe creates a probe that runs the fuzzer binary in Docker.
func NewSubprocessProbe(modelID, binaryPath, binaryName, dockerImage, dockerBinary string) *SubprocessProbe {
	return &SubprocessProbe{
		ModelID:      modelID,
		BinaryPath:   binaryPath,
		BinaryName:   binaryName,
		DockerImage:  dockerImage,
		DockerBinary: dockerBinary,
		CoverageDir:  filepath.Join(filepath.Dir(binaryPath), "..", "coverage"),
	}
}

// Measure runs the seed through the canonical binary and returns the coverage.
func (p *SubprocessProbe) Measure(ctx context.Context, seedPath string) (Result, error) {
	// Hash the seed content for the coverage file name.
	seedHash, err := hashFile(seedPath)
	if err != nil {
		return Result{}, fmt.Errorf("hash seed: %w", err)
	}

	// Prepare coverage output path.
	if err := os.MkdirAll(p.CoverageDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create coverage dir: %w", err)
	}
	coverageFile := filepath.Join(p.CoverageDir, seedHash+".txt")
	// Remove stale coverage file.
	os.Remove(coverageFile)

	// Run the fuzzer binary in Docker with the seed as input.
	binaryDir := filepath.Dir(p.BinaryPath)
	seedName := filepath.Base(seedPath)

	start := time.Now()
	cmd := exec.CommandContext(ctx, p.DockerBinary,
		"run", "--platform", "linux/amd64", "--rm",
		"-e", "FUZZING_ENGINE=libfuzzer",
		"-e", "SANITIZER=address",
		"-e", "ARCHITECTURE=x86_64",
		"-e", "ORCHESTRA_COVERAGE_OUT=/tmp/coverage.txt",
		"-v", binaryDir+":/out",
		"-v", filepath.Dir(seedPath)+":/seeds:ro",
		"-v", p.CoverageDir+":/tmp/covdir",
		p.DockerImage,
		"bash", "-c",
		fmt.Sprintf("export ORCHESTRA_COVERAGE_OUT=/tmp/covdir/%s.txt && /out/%s /seeds/%s",
			seedHash, p.BinaryName, seedName))

	output, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	result := Result{
		ExecutionTime: elapsed,
	}

	if err != nil {
		// Check if it's a crash (exit code != 0 but we still got coverage).
		result.ExitStatus = fmt.Sprintf("error: %v", err)
		result.CrashSignature = string(output)
	} else {
		result.ExitStatus = "ok"
	}

	// Read the coverage file.
	edgeIDs, err := readCoverageFile(coverageFile)
	if err != nil {
		return result, fmt.Errorf("read coverage: %w", err)
	}
	result.EdgeIDs = edgeIDs

	return result, nil
}

// hashFile returns the SHA-256 hex digest of a file.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// readCoverageFile parses the edge coverage output (one edge_id per line).
func readCoverageFile(path string) ([]uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No coverage file means no edges were covered.
		}
		return nil, err
	}
	var edges []uint32
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		id, err := strconv.ParseUint(line, 10, 32)
		if err != nil {
			continue // Skip unparseable lines.
		}
		edges = append(edges, uint32(id))
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i] < edges[j] })
	return edges, nil
}
