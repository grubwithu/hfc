package buildconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

func TestLoadDefaultsAndResolvePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yaml")
	contents := `
schema_version: 1
oss_fuzz:
  checkout: oss-fuzz
  revision: ` + testRevision + `
  codeql_bundle: tools/codeql
artifacts_dir: artifacts
targets:
  - id: zlib-uncompress
    oss_fuzz_project: zlib
    fuzz_target: zlib_uncompress_fuzzer
    language: c++
    primary_source_dir: /src/zlib
    source_revision: ` + testRevision + `
    semantic: {}
    engines:
      - engine: afl
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OSSFuzz.Python != "python3" || cfg.OSSFuzz.Docker != "docker" {
		t.Fatalf("unexpected tool defaults: %#v", cfg.OSSFuzz)
	}
	if !filepath.IsAbs(cfg.OSSFuzz.Checkout) || !filepath.IsAbs(cfg.ArtifactsDir) {
		t.Fatalf("paths were not resolved: %#v", cfg)
	}
	if got := cfg.Targets[0].Semantic.Name; got != "semantic-canonical" {
		t.Fatalf("semantic profile name = %q", got)
	}
	if got := cfg.Targets[0].Engines[0].Name; got != "engine-afl" {
		t.Fatalf("engine profile name = %q", got)
	}
}

func TestValidateRejectsMutableRevisionsAndUnsafeNames(t *testing.T) {
	cfg := validConfig()
	cfg.OSSFuzz.Revision = "master"
	cfg.Targets[0].ID = "bad target"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() unexpectedly succeeded")
	}
	message := err.Error()
	for _, expected := range []string{"pinned hexadecimal commit", "id is invalid"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("Validate() error %q does not contain %q", message, expected)
		}
	}
}

func TestFingerprintIgnoresLocalPathsAndEngineOrder(t *testing.T) {
	first := validConfig()
	first.Targets[0].Engines = append(first.Targets[0].Engines,
		BuildProfile{Name: "engine-honggfuzz", Engine: "honggfuzz", Sanitizer: "address", Architecture: "x86_64"})
	second := *first
	second.OSSFuzz = first.OSSFuzz
	second.OSSFuzz.Checkout = "/different/checkout"
	second.OSSFuzz.CodeQLBundle = "/different/codeql"
	second.Targets = append([]Target(nil), first.Targets...)
	second.Targets[0].Engines = []BuildProfile{first.Targets[0].Engines[1], first.Targets[0].Engines[0]}

	a, err := first.Fingerprint(first.Targets[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Fingerprint(second.Targets[0])
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("fingerprints differ: %s != %s", a, b)
	}
}

func validConfig() *Config {
	return &Config{
		SchemaVersion: CurrentSchemaVersion,
		OSSFuzz: OSSFuzzConfig{
			Checkout:     "/work/oss-fuzz",
			Revision:     testRevision,
			Python:       "python3",
			CodeQLBundle: "/work/codeql",
			Docker:       "docker",
		},
		ArtifactsDir: "/work/artifacts",
		Targets: []Target{{
			ID:               "zlib-uncompress",
			OSSFuzzProject:   "zlib",
			FuzzTarget:       "zlib_uncompress_fuzzer",
			Language:         "c++",
			PrimarySourceDir: "/src/zlib",
			SourceRevision:   testRevision,
			Semantic: BuildProfile{
				Name: "semantic-canonical", Engine: "libfuzzer",
				Sanitizer: "address", Architecture: "x86_64",
			},
			Engines: []BuildProfile{{
				Name: "engine-libfuzzer", Engine: "libfuzzer",
				Sanitizer: "address", Architecture: "x86_64",
			}},
		}},
	}
}
