// Package ossfuzz turns V2 build profiles into reproducible OSS-Fuzz commands.
package ossfuzz

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/grubwithu/orchestra/internal/buildconfig"
)

const (
	projectImagePrefix = "gcr.io/oss-fuzz/"
	baseRunnerImage    = "gcr.io/oss-fuzz-base/base-runner"
)

type Command struct {
	Program string
	Args    []string
	Dir     string
}

func (c Command) Render() string {
	parts := make([]string, 0, len(c.Args)+1)
	parts = append(parts, shellQuote(c.Program))
	for _, arg := range c.Args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

type ProfilePaths struct {
	Root         string
	Out          string
	Work         string
	CodeQLDB     string
	Manifest     string
	TargetBinary string
}

type Planner struct {
	Config   *buildconfig.Config
	RepoRoot string
}

func (p Planner) VerifyCheckout(ctx context.Context) error {
	command := exec.CommandContext(ctx, "git", "-C", p.Config.OSSFuzz.Checkout, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("read OSS-Fuzz revision: %w", err)
	}
	actual := strings.TrimSpace(string(output))
	if !strings.HasPrefix(actual, p.Config.OSSFuzz.Revision) {
		return fmt.Errorf("OSS-Fuzz checkout is %s, config requires %s", actual, p.Config.OSSFuzz.Revision)
	}
	return nil
}

func (p Planner) BuildImage(target buildconfig.Target) Command {
	helper := filepath.Join(p.Config.OSSFuzz.Checkout, "infra", "helper.py")
	return Command{
		Program: p.Config.OSSFuzz.Python,
		Args:    []string{helper, "build_image", target.OSSFuzzProject},
		Dir:     p.Config.OSSFuzz.Checkout,
	}
}

func (p Planner) Paths(target buildconfig.Target, profile buildconfig.BuildProfile) ProfilePaths {
	root := filepath.Join(p.Config.ArtifactsDir, target.ID, profile.Name)
	return ProfilePaths{
		Root:         root,
		Out:          filepath.Join(root, "out"),
		Work:         filepath.Join(root, "work"),
		CodeQLDB:     filepath.Join(root, "work", "codeql-db"),
		Manifest:     filepath.Join(root, "manifest.json"),
		TargetBinary: filepath.Join(root, "out", target.FuzzTarget),
	}
}

func (p Planner) BuildProfile(target buildconfig.Target, profile buildconfig.BuildProfile, semantic bool) (Command, error) {
	paths := p.Paths(target, profile)
	root, err := filepath.Abs(p.RepoRoot)
	if err != nil {
		return Command{}, fmt.Errorf("resolve Orchestra repository: %w", err)
	}
	dockerArgs := []string{
		"run", "--privileged", "--shm-size=2g", "--platform", "linux/amd64", "--rm",
		"-e", "FUZZING_ENGINE=" + profile.Engine,
		"-e", "SANITIZER=" + profile.Sanitizer,
		"-e", "ARCHITECTURE=" + profile.Architecture,
		"-e", "PROJECT_NAME=" + target.OSSFuzzProject,
		"-e", "FUZZING_LANGUAGE=" + target.Language,
		"-e", "HELPER=True",
		"-e", "ORCHESTRA_PROFILE=engine",
		"-e", "ORCHESTRA_PRIMARY_SOURCE_DIR=" + target.PrimarySourceDir,
		"-e", "ORCHESTRA_SOURCE_REVISION=" + target.SourceRevision,
		"-v", paths.Out + ":/out",
		"-v", paths.Work + ":/work",
		"-v", root + ":/opt/orchestra:ro",
		"--entrypoint", "/opt/orchestra/scripts/orchestra-ossfuzz-entrypoint.sh",
	}
	if semantic {
		dockerArgs = replaceEnvironment(dockerArgs, "ORCHESTRA_PROFILE", "semantic-canonical")
		dockerArgs = append(dockerArgs,
			"-e", "ORCHESTRA_CODEQL_DB=/work/codeql-db",
			"-e", "ORCHESTRA_CODEQL_LANGUAGE=cpp",
			"-e", "ORCHESTRA_SOURCE_ROOT=/src",
			"-v", p.Config.OSSFuzz.CodeQLBundle+":/opt/codeql:ro",
		)
	}
	keys := make([]string, 0, len(profile.Environment))
	for key := range profile.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		dockerArgs = append(dockerArgs, "-e", key+"="+profile.Environment[key])
	}
	dockerArgs = append(dockerArgs, projectImagePrefix+target.OSSFuzzProject)
	return Command{Program: p.Config.OSSFuzz.Docker, Args: dockerArgs}, nil
}

func (p Planner) CheckProfile(target buildconfig.Target, profile buildconfig.BuildProfile) (Command, error) {
	paths := p.Paths(target, profile)
	runnerImage, err := p.runnerImage(target)
	if err != nil {
		return Command{}, err
	}
	args := []string{
		"run", "--platform", "linux/amd64", "--rm",
		"-e", "FUZZING_ENGINE=" + profile.Engine,
		"-e", "SANITIZER=" + profile.Sanitizer,
		"-e", "ARCHITECTURE=" + profile.Architecture,
		"-e", "FUZZING_LANGUAGE=" + target.Language,
		"-e", "HELPER=True",
		"-v", paths.Out + ":/out:ro",
		runnerImage, "test_one.py", target.FuzzTarget,
	}
	return Command{Program: p.Config.OSSFuzz.Docker, Args: args}, nil
}

func Prepare(paths ProfilePaths) error {
	for _, path := range []string{paths.Out, paths.Work} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("create build directory %s: %w", path, err)
		}
	}
	if _, err := os.Stat(paths.CodeQLDB); err == nil {
		return fmt.Errorf("CodeQL database already exists at %s; choose a new fingerprint or remove it explicitly", paths.CodeQLDB)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect CodeQL database path: %w", err)
	}
	return nil
}

type Executor struct {
	Stdout io.Writer
	Stderr io.Writer
}

func (e Executor) Run(ctx context.Context, command Command) error {
	cmd := exec.CommandContext(ctx, command.Program, command.Args...)
	cmd.Dir = command.Dir
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed (%s): %w", command.Render(), err)
	}
	return nil
}

func DockerImageDigest(ctx context.Context, docker, image string) (string, error) {
	cmd := exec.CommandContext(ctx, docker, "image", "inspect", "--format={{.Id}}", image)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("inspect Docker image %s: %w", image, err)
	}
	return strings.TrimSpace(string(output)), nil
}

func ProjectImage(project string) string { return projectImagePrefix + project }

func (p Planner) runnerImage(target buildconfig.Target) (string, error) {
	dockerfile := filepath.Join(p.Config.OSSFuzz.Checkout, "projects", target.OSSFuzzProject, "Dockerfile")
	data, err := os.ReadFile(dockerfile)
	if err != nil {
		return "", fmt.Errorf("read OSS-Fuzz project Dockerfile: %w", err)
	}
	const builderPrefix = "gcr.io/oss-fuzz-base/base-builder:"
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "FROM "+builderPrefix) {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "FROM "+builderPrefix))
		if len(fields) == 0 {
			continue
		}
		tag := fields[0]
		if tag != "" {
			return baseRunnerImage + ":" + tag, nil
		}
	}
	return baseRunnerImage, nil
}

func replaceEnvironment(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	prefix := name + "="
	for i := 0; i+1 < len(result); i++ {
		if result[i] == "-e" && strings.HasPrefix(result[i+1], prefix) {
			result[i+1] = prefix + value
			return result
		}
	}
	return append(result, "-e", prefix+value)
}

func shellQuote(value string) string {
	if value != "" && strings.IndexFunc(value, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '-' || r == '_' || r == ':' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) == -1 {
		return value
	}
	return strconv.Quote(value)
}
