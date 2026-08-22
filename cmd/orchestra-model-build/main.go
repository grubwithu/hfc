// Command orchestra-model-build merges CodeQL fact exports and LLVM edge
// manifests into an immutable program_model.sqlite database.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/grubwithu/orchestra/internal/buildconfig"
	"github.com/grubwithu/orchestra/internal/modelbuilder"
)

func main() {
	log.SetFlags(0)
	if err := run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(_ context.Context, args []string) error {
	flags := flag.NewFlagSet("orchestra-model-build", flag.ContinueOnError)
	configPath := flags.String("config", "experiments/targets.yaml", "target manifest")
	targetID := flags.String("target", "", "configured target id")
	modelID := flags.String("model-id", "", "Program Model identifier")
	factsPath := flags.String("facts", "", "path to facts.json (default: <artifacts>/<target>/<profile>/facts.json)")
	edgeManifest := flags.String("edges", "", "path to LLVM edge manifest JSON")
	manifestPath := flags.String("manifest", "", "path to artifact manifest.json")
	schemaPath := flags.String("schema", "schema/program_model.sql", "path to program_model.sql")
	outputPath := flags.String("output", "", "output path for program_model.sqlite")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *targetID == "" {
		return fmt.Errorf("-target is required")
	}
	if *modelID == "" {
		return fmt.Errorf("-model-id is required")
	}

	// Resolve default paths from the config.
	cfg, err := buildconfig.Load(*configPath)
	if err != nil {
		return err
	}
	target, err := cfg.Target(*targetID)
	if err != nil {
		return err
	}

	artifactsDir := cfg.ArtifactsDir
	profileDir := filepath.Join(artifactsDir, target.ID, target.Semantic.Name)

	if *factsPath == "" {
		*factsPath = filepath.Join(profileDir, "facts.json")
	}
	if *manifestPath == "" {
		*manifestPath = filepath.Join(profileDir, "manifest.json")
	}
	if *edgeManifest == "" {
		*edgeManifest = filepath.Join(profileDir, "out", "orchestra-edge-manifest.json")
	}
	if *outputPath == "" {
		*outputPath = filepath.Join(profileDir, "program_model.sqlite")
	}

	// Verify inputs exist.
	for _, path := range []struct{ name, path string }{
		{"facts", *factsPath},
		{"manifest", *manifestPath},
		{"schema", *schemaPath},
	} {
		if _, err := os.Stat(path.path); err != nil {
			return fmt.Errorf("%s not found: %w", path.name, err)
		}
	}
	// Edge manifest is optional (may not exist if the pass was not injected).
	if _, err := os.Stat(*edgeManifest); err != nil {
		log.Printf("warning: edge manifest not found at %s; frontiers will be unmapped", *edgeManifest)
		*edgeManifest = ""
	}

	input := modelbuilder.BuildInput{
		ModelID:      *modelID,
		FactsPath:    *factsPath,
		EdgeManifest: *edgeManifest,
		ManifestPath: *manifestPath,
		SchemaPath:   *schemaPath,
		OutputPath:   *outputPath,
	}

	result, err := modelbuilder.Build(input)
	if err != nil {
		return err
	}

	fmt.Printf("model built: %s\n", result.OutputPath)
	fmt.Printf("  functions: %d\n", result.FunctionCount)
	fmt.Printf("  calls: %d\n", result.CallCount)
	fmt.Printf("  runtime_edges: %d\n", result.EdgeCount)
	fmt.Printf("  frontiers: %d\n", result.FrontierCount)
	fmt.Printf("  tokens: %d\n", result.TokenCount)
	fmt.Printf("  mapping:\n")
	for _, status := range []string{"exact", "ambiguous", "unmapped", "unsupported"} {
		if count, ok := result.MappingCounts[modelbuilder.MappingStatus(status)]; ok && count > 0 {
			fmt.Printf("    %s: %d\n", status, count)
		}
	}
	return nil
}
