// Package buildconfig defines the reproducible build inputs used by Orchestra V2.
package buildconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const CurrentSchemaVersion = 1

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Config struct {
	SchemaVersion int           `yaml:"schema_version" json:"schema_version"`
	OSSFuzz       OSSFuzzConfig `yaml:"oss_fuzz" json:"oss_fuzz"`
	ArtifactsDir  string        `yaml:"artifacts_dir" json:"artifacts_dir"`
	Targets       []Target      `yaml:"targets" json:"targets"`
}

type OSSFuzzConfig struct {
	Checkout     string `yaml:"checkout" json:"checkout"`
	Revision     string `yaml:"revision" json:"revision"`
	Python       string `yaml:"python" json:"python"`
	CodeQLBundle string `yaml:"codeql_bundle" json:"codeql_bundle"`
	Docker       string `yaml:"docker" json:"docker"`
}

type Target struct {
	ID               string         `yaml:"id" json:"id"`
	OSSFuzzProject   string         `yaml:"oss_fuzz_project" json:"oss_fuzz_project"`
	FuzzTarget       string         `yaml:"fuzz_target" json:"fuzz_target"`
	Language         string         `yaml:"language" json:"language"`
	PrimarySourceDir string         `yaml:"primary_source_dir" json:"primary_source_dir"`
	SourceRevision   string         `yaml:"source_revision" json:"source_revision"`
	Semantic         BuildProfile   `yaml:"semantic" json:"semantic"`
	Engines          []BuildProfile `yaml:"engines" json:"engines"`
}

type BuildProfile struct {
	Name         string            `yaml:"name" json:"name"`
	Engine       string            `yaml:"engine" json:"engine"`
	Sanitizer    string            `yaml:"sanitizer" json:"sanitizer"`
	Architecture string            `yaml:"architecture" json:"architecture"`
	Environment  map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read build config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode build config: %w", err)
	}

	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("resolve config directory: %w", err)
	}
	cfg.OSSFuzz.Checkout = resolvePath(base, cfg.OSSFuzz.Checkout)
	cfg.OSSFuzz.CodeQLBundle = resolvePath(base, cfg.OSSFuzz.CodeQLBundle)
	cfg.ArtifactsDir = resolvePath(base, cfg.ArtifactsDir)

	if cfg.OSSFuzz.Python == "" {
		cfg.OSSFuzz.Python = "python3"
	}
	if cfg.OSSFuzz.Docker == "" {
		cfg.OSSFuzz.Docker = "docker"
	}
	for i := range cfg.Targets {
		applyProfileDefaults(&cfg.Targets[i].Semantic, "semantic-canonical")
		for j := range cfg.Targets[i].Engines {
			applyProfileDefaults(&cfg.Targets[i].Engines[j], "")
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	var problems []error
	if c.SchemaVersion != CurrentSchemaVersion {
		problems = append(problems, fmt.Errorf("schema_version must be %d", CurrentSchemaVersion))
	}
	if c.OSSFuzz.Checkout == "" {
		problems = append(problems, errors.New("oss_fuzz.checkout is required"))
	}
	if !isPinnedRevision(c.OSSFuzz.Revision) {
		problems = append(problems, errors.New("oss_fuzz.revision must be a pinned hexadecimal commit"))
	}
	if c.OSSFuzz.CodeQLBundle == "" {
		problems = append(problems, errors.New("oss_fuzz.codeql_bundle is required"))
	}
	if c.ArtifactsDir == "" {
		problems = append(problems, errors.New("artifacts_dir is required"))
	}
	if len(c.Targets) == 0 {
		problems = append(problems, errors.New("at least one target is required"))
	}

	seen := make(map[string]struct{}, len(c.Targets))
	for i := range c.Targets {
		t := &c.Targets[i]
		prefix := fmt.Sprintf("targets[%d]", i)
		if !safeName.MatchString(t.ID) {
			problems = append(problems, fmt.Errorf("%s.id is invalid", prefix))
		} else if _, exists := seen[t.ID]; exists {
			problems = append(problems, fmt.Errorf("duplicate target id %q", t.ID))
		}
		seen[t.ID] = struct{}{}
		if !safeName.MatchString(t.OSSFuzzProject) {
			problems = append(problems, fmt.Errorf("%s.oss_fuzz_project is invalid", prefix))
		}
		if !safeName.MatchString(t.FuzzTarget) {
			problems = append(problems, fmt.Errorf("%s.fuzz_target is invalid", prefix))
		}
		if t.Language != "c" && t.Language != "c++" {
			problems = append(problems, fmt.Errorf("%s.language must be c or c++", prefix))
		}
		cleanDir := filepath.Clean(t.PrimarySourceDir)
		if cleanDir != "/src" && !strings.HasPrefix(cleanDir, "/src/") {
			problems = append(problems, fmt.Errorf("%s.primary_source_dir must be /src or below /src", prefix))
		}
		if !isPinnedRevision(t.SourceRevision) {
			problems = append(problems, fmt.Errorf("%s.source_revision must be a pinned hexadecimal commit", prefix))
		}
		problems = appendProfileProblems(problems, prefix+".semantic", t.Semantic)
		if len(t.Engines) == 0 {
			problems = append(problems, fmt.Errorf("%s.engines must not be empty", prefix))
		}
		profileNames := map[string]struct{}{t.Semantic.Name: {}}
		for j, profile := range t.Engines {
			problems = appendProfileProblems(problems, fmt.Sprintf("%s.engines[%d]", prefix, j), profile)
			if _, exists := profileNames[profile.Name]; exists {
				problems = append(problems, fmt.Errorf("%s has duplicate profile %q", prefix, profile.Name))
			}
			profileNames[profile.Name] = struct{}{}
		}
	}
	return errors.Join(problems...)
}

func (c *Config) Target(id string) (Target, error) {
	for _, target := range c.Targets {
		if target.ID == id {
			return target, nil
		}
	}
	return Target{}, fmt.Errorf("target %q is not configured", id)
}

// Fingerprint returns a deterministic identifier for all declared inputs to a
// target build. Runtime-discovered values such as the Docker image digest and
// binary hashes belong in the artifact manifest rather than this fingerprint.
func (c *Config) Fingerprint(target Target) (string, error) {
	canonical := struct {
		SchemaVersion int           `json:"schema_version"`
		OSSFuzz       OSSFuzzConfig `json:"oss_fuzz"`
		Target        Target        `json:"target"`
	}{c.SchemaVersion, c.OSSFuzz, cloneTarget(target)}
	canonical.OSSFuzz.Checkout = ""
	canonical.OSSFuzz.CodeQLBundle = ""
	canonical.OSSFuzz.Python = ""
	canonical.OSSFuzz.Docker = ""

	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode build fingerprint: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func resolvePath(base, value string) string {
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(base, value))
}

func applyProfileDefaults(profile *BuildProfile, defaultName string) {
	if profile.Name == "" {
		if defaultName != "" {
			profile.Name = defaultName
		} else {
			profile.Name = "engine-" + profile.Engine
		}
	}
	if profile.Engine == "" {
		profile.Engine = "libfuzzer"
	}
	if profile.Sanitizer == "" {
		profile.Sanitizer = "address"
	}
	if profile.Architecture == "" {
		profile.Architecture = "x86_64"
	}
}

func appendProfileProblems(problems []error, prefix string, profile BuildProfile) []error {
	for field, value := range map[string]string{
		"name": profile.Name, "engine": profile.Engine,
		"sanitizer": profile.Sanitizer, "architecture": profile.Architecture,
	} {
		if !safeName.MatchString(value) {
			problems = append(problems, fmt.Errorf("%s.%s is invalid", prefix, field))
		}
	}
	for key := range profile.Environment {
		if !environmentName.MatchString(key) {
			problems = append(problems, fmt.Errorf("%s.environment contains invalid key %q", prefix, key))
		}
	}
	return problems
}

func isPinnedRevision(value string) bool {
	if len(value) < 7 || len(value) > 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func cloneTarget(target Target) Target {
	result := target
	result.Semantic.Environment = cloneMap(target.Semantic.Environment)
	result.Engines = append([]BuildProfile(nil), target.Engines...)
	for i := range result.Engines {
		result.Engines[i].Environment = cloneMap(result.Engines[i].Environment)
	}
	sort.Slice(result.Engines, func(i, j int) bool {
		return result.Engines[i].Name < result.Engines[j].Name
	})
	return result
}

func cloneMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
