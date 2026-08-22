package ossfuzz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grubwithu/orchestra/internal/buildconfig"
)

func TestSemanticPlanWrapsOSSFuzzCompileInsideContainer(t *testing.T) {
	planner, target := testPlanner(t)
	command, err := planner.BuildProfile(target, target.Semantic, true)
	if err != nil {
		t.Fatal(err)
	}
	rendered := command.Render()
	for _, expected := range []string{
		"ORCHESTRA_PROFILE=semantic-canonical",
		"ORCHESTRA_CODEQL_DB=/work/codeql-db",
		"/opt/codeql:ro",
		"/opt/orchestra/scripts/orchestra-ossfuzz-entrypoint.sh",
		"gcr.io/oss-fuzz/zlib",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("command %q does not contain %q", rendered, expected)
		}
	}
}

func TestBuildImageUsesCachedBaseImagesWithoutPrompting(t *testing.T) {
	planner, target := testPlanner(t)
	command := planner.BuildImage(target)
	want := []string{
		"/tmp/oss-fuzz/infra/helper.py",
		"build_image",
		"--no-pull",
		"zlib",
	}
	if strings.Join(command.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("build image arguments = %#v, want %#v", command.Args, want)
	}
}

func TestCheckProfileUsesMatchingBaseRunnerTag(t *testing.T) {
	planner, target := testPlanner(t)
	checkout := t.TempDir()
	projectDir := filepath.Join(checkout, "projects", target.OSSFuzzProject)
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "Dockerfile"),
		[]byte("FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	planner.Config.OSSFuzz.Checkout = checkout
	command, err := planner.CheckProfile(target, target.Engines[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command.Render(), "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04") {
		t.Fatalf("unexpected runner command: %s", command.Render())
	}
}

func TestEngineEnvironmentIsSorted(t *testing.T) {
	planner, target := testPlanner(t)
	profile := target.Engines[0]
	profile.Environment = map[string]string{"ZZZ": "last", "AAA": "first"}
	command, err := planner.BuildProfile(target, profile, false)
	if err != nil {
		t.Fatal(err)
	}
	rendered := command.Render()
	if strings.Index(rendered, "AAA=first") > strings.Index(rendered, "ZZZ=last") {
		t.Fatalf("environment is not sorted: %s", rendered)
	}
}

func testPlanner(t *testing.T) (Planner, buildconfig.Target) {
	t.Helper()
	revision := "0123456789abcdef0123456789abcdef01234567"
	target := buildconfig.Target{
		ID:               "zlib-uncompress",
		OSSFuzzProject:   "zlib",
		FuzzTarget:       "zlib_uncompress_fuzzer",
		Language:         "c++",
		PrimarySourceDir: "/src/zlib",
		SourceRevision:   revision,
		Semantic: buildconfig.BuildProfile{
			Name: "semantic-canonical", Engine: "libfuzzer", Sanitizer: "address", Architecture: "x86_64",
		},
		Engines: []buildconfig.BuildProfile{{
			Name: "engine-libfuzzer", Engine: "libfuzzer", Sanitizer: "address", Architecture: "x86_64",
		}},
	}
	cfg := &buildconfig.Config{
		SchemaVersion: 1,
		OSSFuzz: buildconfig.OSSFuzzConfig{
			Checkout: "/tmp/oss-fuzz", Revision: revision, Python: "python3",
			CodeQLBundle: "/tmp/codeql", Docker: "docker",
		},
		ArtifactsDir: "/tmp/artifacts",
		Targets:      []buildconfig.Target{target},
	}
	return Planner{Config: cfg, RepoRoot: "/tmp/orchestra"}, target
}
