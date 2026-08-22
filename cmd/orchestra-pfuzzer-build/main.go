// Command orchestra-pfuzzer-build builds the pfuzzer static library
// (libfuzzer.a) that Orchestra's OSS-Fuzz builds link against.
//
// pfuzzer extends upstream libFuzzer with V1's HTTP integration (FuzzerHFC.cpp),
// but V2 uses pfuzzer only for the multi-engine main() implementation. The V1
// HTTP client (FuzzerHFC.cpp / FuzzerHFC.h) is excluded from the build by
// patching CMakeLists.txt temporarily before invoking cmake. This keeps
// pfuzzer buildable for V2 without modifying the pfuzzer submodule's
// internal sources.
//
// Output:
//   <pfuzzer-src>/build/libfuzzer.a       — static library linked into fuzzer
//
//   binaries built by `orchestra-ossfuzz build`. The OSS-Fuzz builder mounts
//   this file at /opt/pfuzzer/libFuzzer.a and sets
//   LIB_FUZZING_ENGINE=/opt/pfuzzer/libFuzzer.a.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

func main() {
	log.SetFlags(0)
	if err := run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("orchestra-pfuzzer-build", flag.ContinueOnError)
	pfuzzerDir := flags.String("pfuzzer", "pfuzzer", "path to the pfuzzer submodule (relative to repo root or absolute)")
	// Output goes to the repo's top-level build/ tree (already .gitignored)
	// to avoid leaving artifacts inside the pfuzzer submodule's working
	// tree (which would mark the submodule dirty).
	outDir := flags.String("out", "build/v2/pfuzzer-build", "output directory; libfuzzer.a is written here. Default is repo-relative under build/, which .gitignore covers.")
	// Path to the V2 patch files for FuzzerHFC.{h,cpp}. The default
	// `pfuzzer-hfc-patch/` sits at the repo root (committed) and holds
	// the V2 HTTP-client implementation. We overlay these onto the
	// submodule for the build, then restore the originals.
	hfcPatchDir := flags.String("hfc-patch", "pfuzzer-hfc-patch", "directory containing V2 versions of FuzzerHFC.h and FuzzerHFC.cpp")
	jobs := flags.Int("jobs", 0, "parallel build jobs (0 = nproc)")
	if err := flags.Parse(args); err != nil {
		return err
	}

	pfuzzerSrc, err := filepath.Abs(*pfuzzerDir)
	if err != nil {
		return fmt.Errorf("resolve pfuzzer dir: %w", err)
	}
	if !fileExists(filepath.Join(pfuzzerSrc, "CMakeLists.txt")) {
		return fmt.Errorf("pfuzzer CMakeLists.txt not found at %s; pass -pfuzzer=... or ensure submodule is initialized", pfuzzerSrc)
	}

	hfcPatch, err := filepath.Abs(*hfcPatchDir)
	if err != nil {
		return fmt.Errorf("resolve hfc-patch dir: %w", err)
	}
	for _, fname := range []string{"FuzzerHFC.h", "FuzzerHFC.cpp"} {
		if !fileExists(filepath.Join(hfcPatch, fname)) {
			return fmt.Errorf("V2 patch file %s/%s not found; pass -hfc-patch=...", hfcPatch, fname)
		}
	}

	outputDir, err := filepath.Abs(*outDir)
	if err != nil {
		return fmt.Errorf("resolve output dir: %w", err)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Backup the originals we are about to modify. The CMakeLists.txt
	// exclusion and the FuzzerHFC.h/.cpp overlay both need restoration.
	origCMake := filepath.Join(pfuzzerSrc, "CMakeLists.txt")
	backupPath := origCMake + ".v2-backup"
	if err := backupFile(origCMake, backupPath); err != nil {
		return fmt.Errorf("backup CMakeLists.txt: %w", err)
	}
	defer func() {
		if err := restoreFile(backupPath, origCMake); err != nil {
			log.Printf("warning: failed to restore %s: %v", origCMake, err)
		}
	}()

	hfcBackups := []string{}
	defer func() {
		// Restore the original FuzzerHFC.{h,cpp} (and nested submodule
		// state) so the pfuzzer submodule working tree is clean.
		for _, backup := range hfcBackups {
			orig := filepath.Join(pfuzzerSrc, filepath.Base(backup))
			if err := restoreFile(backup, orig); err != nil {
				log.Printf("warning: failed to restore %s: %v", orig, err)
			}
		}
	}()

	// V2 build: exclude V1-only FuzzerHFC.cpp's V1-only typedef quirk.
	// The exclusion is a sed comment, not a deletion, so the original
	// is fully restored after build completes.
	if err := patchCMakeListsTxt(origCMake); err != nil {
		return fmt.Errorf("patch CMakeLists.txt: %w", err)
	}

	// Overlay the V2 HTTP client onto the submodule. This keeps the
	// pfuzzer submodule's git HEAD at the official commit while still
	// using the V2 wire format.
	for _, fname := range []string{"FuzzerHFC.h", "FuzzerHFC.cpp"} {
		src := filepath.Join(hfcPatch, fname)
		dst := filepath.Join(pfuzzerSrc, fname)
		backup := dst + ".v2-backup"
		if err := backupFile(dst, backup); err != nil {
			return fmt.Errorf("backup %s: %w", dst, err)
		}
		hfcBackups = append(hfcBackups, backup)
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("overlay %s -> %s: %w", src, dst, err)
		}
	}

	// Run cmake configure + build.
	cmd := exec.CommandContext(ctx, "cmake",
		"-S", pfuzzerSrc,
		"-B", outputDir,
		// -fpermissive: V1's FuzzerHFC.h has a struct field and a typedef
		// alias that share names. GCC 12 rejects this; -fpermissive
		// restores the pre-GCC-12 behavior so we don't modify the
		// upstream pfuzzer submodule. We also silence warnings (-w)
		// since we are not modifying pfuzzer internal code.
		"-DCMAKE_CXX_FLAGS=-w -fpermissive",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cmake configure: %w", err)
	}

	nJobs := *jobs
	if nJobs <= 0 {
		nJobs = nproc()
	}
	makeCmd := exec.CommandContext(ctx, "make", "-j"+itoa(nJobs))
	makeCmd.Dir = outputDir
	makeCmd.Stdout = os.Stdout
	makeCmd.Stderr = os.Stderr
	if err := makeCmd.Run(); err != nil {
		return fmt.Errorf("make: %w", err)
	}

	// Verify output exists.
	libPath := filepath.Join(outputDir, "libfuzzer.a")
	if !fileExists(libPath) {
		return fmt.Errorf("build succeeded but %s not found", libPath)
	}

	fmt.Printf("Built pfuzzer libfuzzer.a at %s\n", libPath)
	return nil
}

// patchCMakeListsTxt excludes the V1-only FuzzerHFC.cpp file from the pfuzzer
// library source list. The exclusion is a sed-based comment, restored after
// build by the deferred restoreFile call in run().
func patchCMakeListsTxt(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Comment out "  FuzzerHFC.cpp" so cmake skips it. The match must be exact
	// to avoid corrupting unrelated lines (e.g., comments).
	re := regexp.MustCompile(`(?m)^(  FuzzerHFC\.cpp)$`)
	patched := re.ReplaceAll(data, []byte("# $1  # excluded by orchestra-pfuzzer-build (V1-only HTTP client)"))
	if err := os.WriteFile(path, patched, 0o644); err != nil {
		return err
	}
	return nil
}

func backupFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func restoreFile(backup, dst string) error {
	if err := os.Rename(backup, dst); err != nil {
		// Fallback: copy content if rename fails (e.g., cross-device).
		data, err2 := os.ReadFile(backup)
		if err2 != nil {
			return fmt.Errorf("rename: %w; read backup: %v", err, err2)
		}
		if err3 := os.WriteFile(dst, data, 0o644); err3 != nil {
			return fmt.Errorf("rename: %w; write: %v", err, err3)
		}
		return os.Remove(backup)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func nproc() int {
	out, err := exec.Command("nproc").Output()
	if err != nil {
		return 1
	}
	var n int
	if _, err := fmt.Sscanf(string(out), "%d", &n); err != nil || n <= 0 {
		return 1
	}
	return n
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
