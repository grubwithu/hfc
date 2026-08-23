package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/grubwithu/orchestra/internal/artifact"
	"github.com/grubwithu/orchestra/internal/buildconfig"
	"github.com/grubwithu/orchestra/internal/factexport"
	"github.com/grubwithu/orchestra/internal/ossfuzz"
)

// llvmPassVersion is the specification version of the Orchestra edge ID pass.
// It remains a reservation until the pass is implemented under llvm/id-pass.
const llvmPassVersion = "spec-0.1"

// qlPackVersion is the name@version string from codeql/orchestra-model/qlpack.yml.
const qlPackVersion = "grubwithu/orchestra-model@0.1.0"

func main() {
	log.SetFlags(0)
	if err := run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "validate":
		return validate(args[1:])
	case "plan":
		return plan(ctx, args[1:])
	case "build":
		return build(ctx, args[1:])
	case "export-facts":
		return exportFacts(ctx, args[1:])
	default:
		return usageError()
	}
}

func validate(args []string) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	configPath := flags.String("config", "experiments/targets.yaml", "target manifest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := buildconfig.Load(*configPath)
	if err != nil {
		return err
	}
	fmt.Printf("valid schema=%d targets=%d\n", cfg.SchemaVersion, len(cfg.Targets))
	for _, target := range cfg.Targets {
		fingerprint, err := cfg.Fingerprint(target)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s\n", target.ID, fingerprint)
	}
	return nil
}

func plan(ctx context.Context, args []string) error {
	options, err := parseBuildOptions("plan", args)
	if err != nil {
		return err
	}
	cfg, target, planner, profiles, err := loadBuild(options)
	if err != nil {
		return err
	}
	_ = cfg
	if err := planner.VerifyCheckout(ctx); err != nil {
		return err
	}
	fmt.Println(planner.BuildImage(target).Render())
	for _, selected := range profiles {
		command, err := planner.BuildProfile(target, selected.profile, selected.semantic)
		if err != nil {
			return err
		}
		fmt.Println(command.Render())
		check, err := planner.CheckProfile(target, selected.profile)
		if err != nil {
			return err
		}
		fmt.Println(check.Render())
	}
	return nil
}

func build(ctx context.Context, args []string) error {
	options, err := parseBuildOptions("build", args)
	if err != nil {
		return err
	}
	cfg, target, planner, profiles, err := loadBuild(options)
	if err != nil {
		return err
	}
	if err := planner.VerifyCheckout(ctx); err != nil {
		return err
	}
	// Build the prebuilt pfuzzer libFuzzer.a first; OSS-Fuzz containers
	// link it via LIB_FUZZING_ENGINE=/opt/pfuzzer/libFuzzer.a (see T6 in
	// docs/v2/ROADMAP.md). The build is a no-op if the artifact is
	// already up-to-date.
	if err := runPfuzzerBuild(ctx, planner.RepoRoot); err != nil {
		return fmt.Errorf("build pfuzzer libFuzzer.a: %w", err)
	}

	executor := ossfuzz.Executor{Stdout: os.Stdout, Stderr: os.Stderr}
	// Skip build_image if the Docker image already exists locally.
	image := ossfuzz.ProjectImage(target.OSSFuzzProject)
	if _, err := ossfuzz.DockerImageDigest(ctx, cfg.OSSFuzz.Docker, image); err != nil {
		if err := executor.Run(ctx, planner.BuildImage(target)); err != nil {
			return err
		}
	}
	imageDigest, err := ossfuzz.DockerImageDigest(ctx, cfg.OSSFuzz.Docker, image)
	if err != nil {
		return err
	}
	definitionHash, err := projectDefinitionHash(cfg, target)
	if err != nil {
		return err
	}
	fingerprint, err := cfg.Fingerprint(target)
	if err != nil {
		return err
	}

	// Collect provenance from the build image. Non-fatal: if it fails,
	// continue with empty provenance so the build still succeeds.
	provenance, err := collectProvenance(ctx, cfg, target, image)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: collect build provenance failed: %v\n", err)
	}

	for _, selected := range profiles {
		paths := planner.Paths(target, selected.profile)
		if err := ossfuzz.Prepare(paths); err != nil {
			return err
		}
		command, err := planner.BuildProfile(target, selected.profile, selected.semantic)
		if err != nil {
			return err
		}
		if err := executor.Run(ctx, command); err != nil {
			return err
		}
		check, err := planner.CheckProfile(target, selected.profile)
		if err != nil {
			return err
		}
		if err := executor.Run(ctx, check); err != nil {
			return err
		}
		binaryHash, err := artifact.HashFile(paths.TargetBinary)
		if err != nil {
			return fmt.Errorf("hash target binary: %w", err)
		}
		codeQLPath := ""
		if selected.semantic {
			if stat, err := os.Stat(paths.CodeQLDB); err != nil || !stat.IsDir() {
				return fmt.Errorf("CodeQL database was not created at %s", paths.CodeQLDB)
			}
			codeQLPath = paths.CodeQLDB
		}
		manifest := artifact.Manifest{
			CreatedAt:             time.Now().UTC(),
			BuildFingerprint:      fingerprint,
			OSSFuzzRevision:       cfg.OSSFuzz.Revision,
			OSSFuzzProject:        target.OSSFuzzProject,
			ProjectDefinitionHash: definitionHash,
			FuzzTarget:            target.FuzzTarget,
			SourceRevision:        target.SourceRevision,
			SourceTreeHash:        provenance.SourceTreeHash,
			PrimarySourceDir:      target.PrimarySourceDir,
			Profile:               selected.profile.Name,
			Engine:                selected.profile.Engine,
			Sanitizer:             selected.profile.Sanitizer,
			Architecture:          selected.profile.Architecture,
			CompilerVersion:       provenance.CompilerVersion,
			CompilerFlagsHash:     provenance.CompilerFlagsHash,
			DockerImage:           image,
			DockerImageDigest:     imageDigest,
			CodeQLVersion:         provenance.CodeQLVersion,
			QLPackVersion:         qlPackVersion,
			LLVMPassVersion:       llvmPassVersion,
			BinaryPath:            paths.TargetBinary,
			BinarySHA256:          binaryHash,
			CodeQLDatabasePath:    codeQLPath,
			Environment:           selected.profile.Environment,
		}
		if err := artifact.Write(paths.Manifest, manifest); err != nil {
			return err
		}
		fmt.Printf("built %s profile=%s manifest=%s\n", target.ID, selected.profile.Name, paths.Manifest)
	}
	return nil
}

type buildOptions struct {
	configPath string
	targetID   string
	profiles   string
	repoRoot   string
}

type selectedProfile struct {
	profile  buildconfig.BuildProfile
	semantic bool
}

func parseBuildOptions(name string, args []string) (buildOptions, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := flags.String("config", "experiments/targets.yaml", "target manifest")
	targetID := flags.String("target", "", "configured target id")
	profiles := flags.String("profiles", "semantic-canonical", "comma-separated profile names or all")
	repoRoot := flags.String("repo-root", ".", "Orchestra repository root mounted into the builder")
	if err := flags.Parse(args); err != nil {
		return buildOptions{}, err
	}
	if *targetID == "" {
		return buildOptions{}, errors.New("-target is required")
	}
	return buildOptions{*configPath, *targetID, *profiles, *repoRoot}, nil
}

func loadBuild(options buildOptions) (*buildconfig.Config, buildconfig.Target, ossfuzz.Planner, []selectedProfile, error) {
	cfg, err := buildconfig.Load(options.configPath)
	if err != nil {
		return nil, buildconfig.Target{}, ossfuzz.Planner{}, nil, err
	}
	target, err := cfg.Target(options.targetID)
	if err != nil {
		return nil, buildconfig.Target{}, ossfuzz.Planner{}, nil, err
	}
	root, err := filepath.Abs(options.repoRoot)
	if err != nil {
		return nil, buildconfig.Target{}, ossfuzz.Planner{}, nil, err
	}
	profiles, err := selectProfiles(target, options.profiles)
	if err != nil {
		return nil, buildconfig.Target{}, ossfuzz.Planner{}, nil, err
	}
	return cfg, target, ossfuzz.Planner{Config: cfg, RepoRoot: root}, profiles, nil
}

func selectProfiles(target buildconfig.Target, requested string) ([]selectedProfile, error) {
	available := map[string]selectedProfile{
		target.Semantic.Name: {target.Semantic, true},
	}
	for _, profile := range target.Engines {
		available[profile.Name] = selectedProfile{profile, false}
	}
	if requested == "all" {
		result := []selectedProfile{{target.Semantic, true}}
		for _, profile := range target.Engines {
			result = append(result, selectedProfile{profile, false})
		}
		return result, nil
	}
	var result []selectedProfile
	for _, name := range strings.Split(requested, ",") {
		name = strings.TrimSpace(name)
		profile, exists := available[name]
		if !exists {
			return nil, fmt.Errorf("profile %q is not configured for target %q", name, target.ID)
		}
		result = append(result, profile)
	}
	return result, nil
}

func projectDefinitionHash(cfg *buildconfig.Config, target buildconfig.Target) (string, error) {
	directory := filepath.Join(cfg.OSSFuzz.Checkout, "projects", target.OSSFuzzProject)
	for _, name := range []string{"project.yaml", "Dockerfile", "build.sh"} {
		path := filepath.Join(directory, name)
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("required OSS-Fuzz project file %s: %w", path, err)
		}
	}
	return artifact.HashTree(directory)
}

// buildProvenance carries discovered provenance from the build environment.
type buildProvenance struct {
	SourceTreeHash    string
	CompilerVersion   string
	CompilerFlagsHash string
	CodeQLVersion     string
}

// collectProvenance queries the Docker build image for compiler version,
// source tree hash, and CodeQL version. Compiler flags hash is derived from
// the flags that OSS-Fuzz compile exports for the configured engine/sanitizer.
func collectProvenance(ctx context.Context, cfg *buildconfig.Config, target buildconfig.Target, image string) (buildProvenance, error) {
	var p buildProvenance

	// Compiler version: run clang --version inside the project image.
	compilerVersion, err := dockerOutput(ctx, cfg.OSSFuzz.Docker, image,
		"bash", "-c", "clang --version | head -1")
	if err != nil {
		return p, fmt.Errorf("get compiler version: %w", err)
	}
	p.CompilerVersion = strings.TrimSpace(compilerVersion)

	// Source tree hash: git rev-parse the tree object at the pinned revision.
	sourceTreeHash, err := dockerOutput(ctx, cfg.OSSFuzz.Docker, image,
		"git", "-C", target.PrimarySourceDir, "rev-parse", target.SourceRevision+"^{tree}")
	if err != nil {
		return p, fmt.Errorf("get source tree hash: %w", err)
	}
	p.SourceTreeHash = strings.TrimSpace(sourceTreeHash)

	// CodeQL version: run codeql version on the host bundle.
	codeqlBin := filepath.Join(cfg.OSSFuzz.CodeQLBundle, "codeql")
	codeqlVersion, err := exec.CommandContext(ctx, codeqlBin, "version", "--format=json").Output()
	if err != nil {
		// Fall back to plain text if JSON is unsupported.
		text, err2 := exec.CommandContext(ctx, codeqlBin, "version").Output()
		if err2 != nil {
			return p, fmt.Errorf("get CodeQL version: %w", err2)
		}
		p.CodeQLVersion = strings.TrimSpace(string(text))
	} else {
		p.CodeQLVersion = strings.TrimSpace(string(codeqlVersion))
	}

	// Compiler flags hash: derive from the flags the compile script exports.
	// We capture CFLAGS and CXXFLAGS by running compile in a dry listing mode.
	flagsHash, err := computeCompilerFlagsHash(ctx, cfg, target, image)
	if err != nil {
		return p, fmt.Errorf("compute compiler flags hash: %w", err)
	}
	p.CompilerFlagsHash = flagsHash

	return p, nil
}

// computeCompilerFlagsHash captures the effective CFLAGS and CXXFLAGS from
// the OSS-Fuzz compile environment by invoking the compile script's
// environment without running the actual build.
func computeCompilerFlagsHash(ctx context.Context, cfg *buildconfig.Config, target buildconfig.Target, image string) (string, error) {
	// The OSS-Fuzz compile script exports CFLAGS and CXXFLAGS. We capture them
	// by running a bash command that sources the compile environment.
	script := `set -eu
export FUZZING_ENGINE=` + target.Semantic.Engine + `
export SANITIZER=` + target.Semantic.Sanitizer + `
export ARCHITECTURE=` + target.Semantic.Architecture + `
export FUZZING_LANGUAGE=` + target.Language + `
export SRC=/src
export WORK=/work
export OUT=/out
# Source the libfuzzer compile environment, then print the flags.
. /usr/local/bin/compile_libfuzzer 2>/dev/null || true
echo "CFLAGS=${CFLAGS:-}"
echo "CXXFLAGS=${CXXFLAGS:-}"
`
	output, err := dockerOutput(ctx, cfg.OSSFuzz.Docker, image,
		"bash", "-c", script)
	if err != nil {
		return "", fmt.Errorf("capture compiler flags: %w", err)
	}
	hash := sha256.New()
	hash.Write([]byte(output))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// runPfuzzerBuild ensures the prebuilt pfuzzer libFuzzer.a exists before
// OSS-Fuzz containers are launched. The build is incremental: a cached
// artifact is reused. If the build fails, the error is returned to the
// caller; we do not silently fall back to upstream libFuzzer because the
// resulting binary would lose multi-engine fork coordination.
func runPfuzzerBuild(ctx context.Context, repoRoot string) error {
	pfuzzerA := filepath.Join(repoRoot, "build", "v2", "pfuzzer-build", "libfuzzer.a")
	if _, err := os.Stat(pfuzzerA); err == nil {
		// Already built; skip rebuild.
		return nil
	}
	log.Printf("Building prebuilt pfuzzer libFuzzer.a ...")
	cmd := exec.CommandContext(ctx, "go", "run",
		filepath.Join(repoRoot, "cmd", "orchestra-pfuzzer-build"),
		"-pfuzzer", filepath.Join(repoRoot, "pfuzzer"),
		"-out", filepath.Dir(pfuzzerA),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// dockerOutput runs a command in a Docker container and returns stdout.
func dockerOutput(ctx context.Context, docker, image string, args ...string) (string, error) {
	cmdArgs := []string{"run", "--platform", "linux/amd64", "--rm"}
	cmdArgs = append(cmdArgs, args...)
	cmdArgs = append(cmdArgs, image)
	cmd := exec.CommandContext(ctx, docker, cmdArgs...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func exportFacts(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("export-facts", flag.ContinueOnError)
	configPath := flags.String("config", "experiments/targets.yaml", "target manifest")
	targetID := flags.String("target", "", "configured target id")
	codeqlBinary := flags.String("codeql", "tools/codeql/codeql", "CodeQL CLI binary")
	outputPath := flags.String("output", "", "output JSON path (default: <artifacts>/<target>/semantic-canonical/facts.json)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *targetID == "" {
		return errors.New("-target is required")
	}
	cfg, err := buildconfig.Load(*configPath)
	if err != nil {
		return err
	}
	target, err := cfg.Target(*targetID)
	if err != nil {
		return err
	}
	// Resolve paths relative to the config file.
	artifactsDir := cfg.ArtifactsDir
	databasePath := filepath.Join(artifactsDir, target.ID, target.Semantic.Name, "work", "codeql-db")
	if _, err := os.Stat(databasePath); err != nil {
		return fmt.Errorf("CodeQL database not found at %s; run 'build' first: %w", databasePath, err)
	}
	output := *outputPath
	if output == "" {
		output = filepath.Join(artifactsDir, target.ID, target.Semantic.Name, "facts.json")
	}
	qlPackDir := filepath.Join("codeql", "orchestra-model")
	export, err := factexport.Run(ctx, *codeqlBinary, qlPackDir, databasePath)
	if err != nil {
		return err
	}
	if err := factexport.Write(output, export); err != nil {
		return err
	}
	fmt.Printf("exported facts: %d queries, output=%s\n", len(export.Queries), output)
	for _, q := range export.Queries {
		fmt.Printf("  %s: %d rows\n", q.Name, q.ResultCount)
	}
	return nil
}

func usageError() error {
	return errors.New("usage: orchestra-ossfuzz <validate|plan|build|export-facts> [options]")
}
