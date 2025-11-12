package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/grubwithu/hfc/internal/analysis"
	"github.com/grubwithu/hfc/internal/webcore"
)

func main() {
	// Define command line arguments
	programPath := flag.String("program", "", "Program path, format: -program=xx.out")
	profilePath := flag.String("profile", "", "Program profile file path, format: -profile=fuzzerLogFile-**.yaml")
	callTreePath := flag.String("calltree", "", "Call tree file path, format: -calltree=fuzzerLogFile-**.data")
	port := flag.Int("port", 8080, "Port number for the web server (default: 8080), format: -port=8080")
	help := flag.Bool("h", false, "Display help information")

	// Parse command line arguments
	flag.Parse()

	// Show help information and exit if -h is provided
	if *help || *programPath == "" || *profilePath == "" || *callTreePath == "" {
		fmt.Println("Program Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Check whether llvm-profdata and llvm-cov are installed
	if _, err := exec.LookPath("llvm-profdata"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: llvm-profdata is not installed\n")
		return
	}
	if _, err := exec.LookPath("llvm-cov"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: llvm-cov is not installed\n")
		return
	}

	// Parse the YAML file and get CallTree
	staticData, err := analysis.ParseProfileFromYAML(*profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing YAML: %v\n", err)
		return
	}

	callTree, err := analysis.ParseCallTreeFromData(*callTreePath, staticData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing call tree data: %v\n", err)
		return
	}

	webServer := webcore.NewServer(*port, programPath, callTree)
	webServer.Start()

}
