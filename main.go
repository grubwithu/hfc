package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/grubwithu/hfc/internal/analysis"
	"github.com/grubwithu/hfc/internal/webcore"
)

func main() {
	// Define command line arguments
	programPath := flag.String("program", "", "Program path, format: -program=xx.out")
	staticDataPath := flag.String("staticdata", "", "Static data file path, format: -staticdata=xx.yaml")
	port := flag.Int("port", 8080, "Port number for the web server (default: 8080), format: -port=8080")
	help := flag.Bool("h", false, "Display help information")

	// Parse command line arguments
	flag.Parse()

	// Show help information and exit if -h is provided
	if *help || *programPath == "" || *staticDataPath == "" {
		fmt.Println("Program Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Check whether llvm-profdata and llvm-cov are installed
	if _, err := os.Stat("llvm-profdata"); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: llvm-profdata is not installed\n")
		return
	}
	if _, err := os.Stat("llvm-cov"); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: llvm-cov is not installed\n")
		return
	}

	// Parse the YAML file and get CallTree
	staticData, err := analysis.ParseStaticDataFromYAML(*staticDataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing YAML: %v\n", err)
		return
	}

	webServer := webcore.NewServer(*port, programPath, staticData)
	webServer.Start()

}

func test(programPath *string, fuzzerData *analysis.ProgramStaticData) {
	tempDir, err := os.MkdirTemp("", "hfc_run_")
	if err != nil {
		fmt.Printf("failed to create temporary directory: %v", err)
		return
	}

	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			fmt.Printf("Warning: failed to remove temporary directory %s: %v\n", tempDir, err)
		}
	}()

	// echo 0 > tempDir/seed
	seedPath := fmt.Sprintf("%s/seed", tempDir)
	if err := os.WriteFile(seedPath, []byte("0555"), 0644); err != nil {
		fmt.Printf("failed to write seed file: %v", err)
		return
	}

	// Run the program once with the seed file
	programCoverageData, err := analysis.RunOnce(*programPath, tempDir)
	if err != nil {
		fmt.Printf("failed to run program once: %v", err)
		return
	}

	// Build the call tree
	callTree, err := analysis.BuildCallTree(fuzzerData)
	if err != nil {
		fmt.Printf("failed to build call tree: %v", err)
		return
	}

	// Apply the coverage count to the call tree
	callTree.ApplyCount(&programCoverageData)

}
