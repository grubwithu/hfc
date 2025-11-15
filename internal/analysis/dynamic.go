package analysis

// Add the bytes package to the imports
import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

type FunctionCoverage struct {
	// branches
	Count     int      `json:"count"`
	FileNames []string `json:"filenames"`
	// mcdc_records
	Name string `json:"name"`
	// regions
}

type ProgramCoverageData struct {
	CorpusCount int

	// Files
	Functions []FunctionCoverage `json:"functions"`
	// totals
}

type ProgramCoverageFile struct {
	Data    []ProgramCoverageData `json:"data"`
	Type    string                `json:"type"`
	Version string                `json:"version"`
}

// runOnce creates a temporary directory, executes shell commands,
// and analyzes the resulting files
func RunOnce(programPath string, corpusPath string) (ProgramCoverageData, error) {
	// 1. Create a temporary directory
	workDir, err := os.MkdirTemp("", "hfc_run_")
	if err != nil {
		return ProgramCoverageData{}, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	tempDir, err := os.MkdirTemp(workDir, "corpus")
	if err != nil {
		return ProgramCoverageData{}, fmt.Errorf("failed to create corpus directory: %w", err)
	}

	// Clean up the temporary directory when done
	defer func() {
		if err := os.RemoveAll(workDir); err != nil {
			log.Printf("Warning: failed to remove temporary directory %s: %v\n", workDir, err)
		}
	}()

	// Transform programPath to absolute path
	programPath, err = filepath.Abs(programPath)
	if err != nil {
		return ProgramCoverageData{}, fmt.Errorf("failed to get absolute path of program: %w", err)
	}

	// 2. Execute shell command
	cmd := exec.Command(programPath, tempDir, corpusPath, "-merge=1")
	cmd.Dir = workDir
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return ProgramCoverageData{}, fmt.Errorf("command execution failed: %w", err)
	}

	// 3. Find default.profraw in tempDir
	defaultProfrawPath := filepath.Join(workDir, "default.profraw")
	if _, err := os.Stat(defaultProfrawPath); os.IsNotExist(err) {
		return ProgramCoverageData{}, fmt.Errorf("default.profraw not found in %s", workDir)
	}

	// 4. Running command to process default.profraw
	cmd = exec.Command("llvm-profdata", "merge", "-sparse", defaultProfrawPath, "-o", "merged_cov.profdata")
	cmd.Dir = workDir
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return ProgramCoverageData{}, fmt.Errorf("command execution failed: %w", err)
	}

	cmd = exec.Command("llvm-cov", "export", "-instr-profile", "merged_cov.profdata", "-object="+programPath)
	cmd.Dir = workDir
	var outBuffer bytes.Buffer // Create a buffer to capture stdout
	cmd.Stdout = &outBuffer
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return ProgramCoverageData{}, fmt.Errorf("command execution failed: %w", err)
	}

	llvm_cov_export := outBuffer.String()
	// 5. Unmarshal llvm_cov_export as a ProgramCoverageData
	var programCoverageFile ProgramCoverageFile
	err = json.Unmarshal([]byte(llvm_cov_export), &programCoverageFile)
	if err != nil {
		return ProgramCoverageData{}, fmt.Errorf("error parsing JSON: %w", err)
	}

	if len(programCoverageFile.Data) > 1 {
		log.Println("Attention: more than one ProgramCoverageData found in the JSON file")
	}

	// 6. Get the number of files in corpusPath
	dirEntries, err := os.ReadDir(corpusPath)
	if err != nil {
		return ProgramCoverageData{}, fmt.Errorf("failed to read corpus directory: %w", err)
	}
	programCoverageFile.Data[0].CorpusCount = len(dirEntries)

	return programCoverageFile.Data[0], nil
}
