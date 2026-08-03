package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grubwithu/orchestra/internal/artifact"
	"github.com/grubwithu/orchestra/internal/buildconfig"
	"github.com/grubwithu/orchestra/internal/ossfuzz"
)

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
	executor := ossfuzz.Executor{Stdout: os.Stdout, Stderr: os.Stderr}
	if err := executor.Run(ctx, planner.BuildImage(target)); err != nil {
		return err
	}
	image := ossfuzz.ProjectImage(target.OSSFuzzProject)
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
			PrimarySourceDir:      target.PrimarySourceDir,
			Profile:               selected.profile.Name,
			Engine:                selected.profile.Engine,
			Sanitizer:             selected.profile.Sanitizer,
			Architecture:          selected.profile.Architecture,
			DockerImage:           image,
			DockerImageDigest:     imageDigest,
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

func usageError() error {
	return errors.New("usage: orchestra-ossfuzz <validate|plan|build> [options]")
}
