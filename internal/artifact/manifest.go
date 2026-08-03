// Package artifact records immutable build outputs and their provenance.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const SchemaVersion = 1

type Manifest struct {
	SchemaVersion         int               `json:"schema_version"`
	CreatedAt             time.Time         `json:"created_at"`
	BuildFingerprint      string            `json:"build_fingerprint"`
	OSSFuzzRevision       string            `json:"oss_fuzz_revision"`
	OSSFuzzProject        string            `json:"oss_fuzz_project"`
	ProjectDefinitionHash string            `json:"project_definition_hash,omitempty"`
	FuzzTarget            string            `json:"fuzz_target"`
	SourceRevision        string            `json:"source_revision"`
	PrimarySourceDir      string            `json:"primary_source_dir"`
	Profile               string            `json:"profile"`
	Engine                string            `json:"engine"`
	Sanitizer             string            `json:"sanitizer"`
	Architecture          string            `json:"architecture"`
	DockerImage           string            `json:"docker_image"`
	DockerImageDigest     string            `json:"docker_image_digest,omitempty"`
	BinaryPath            string            `json:"binary_path"`
	BinarySHA256          string            `json:"binary_sha256"`
	CodeQLDatabasePath    string            `json:"codeql_database_path,omitempty"`
	Environment           map[string]string `json:"environment,omitempty"`
}

func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func HashFiles(paths ...string) (string, error) {
	hash := sha256.New()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if _, err := fmt.Fprintf(hash, "%s\x00", filepath.Base(path)); err != nil {
			return "", err
		}
		if _, err := hash.Write(data); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// HashTree covers every regular file and symlink in an OSS-Fuzz project
// definition, including harness sources copied beside build.sh.
func HashTree(root string) (string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range paths {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return "", err
		}
		if _, err := fmt.Fprintf(hash, "%s\x00", filepath.ToSlash(relative)); err != nil {
			return "", err
		}
		if target, err := os.Readlink(path); err == nil {
			if _, err := fmt.Fprintf(hash, "symlink:%s\x00", target); err != nil {
				return "", err
			}
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if _, err := hash.Write(data); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func Write(path string, manifest Manifest) error {
	manifest.SchemaVersion = SchemaVersion
	if manifest.CreatedAt.IsZero() {
		manifest.CreatedAt = time.Now().UTC()
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode artifact manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create manifest directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("create manifest temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return fmt.Errorf("set manifest mode: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close manifest: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish manifest: %w", err)
	}
	return nil
}
