// Command orchestra-pfuzzer-build builds the pfuzzer static library
// (libfuzzer.a) that Orchestra's OSS-Fuzz builds link against.
//
// pfuzzer extends upstream libFuzzer with V1's HTTP integration
// (FuzzerHFC.{h,cpp}), but V2 uses pfuzzer only for the multi-engine
// main() implementation. The V1 HTTP client is replaced at build time
// by the V2 client from `pfuzzer-hfc-patch/`.
//
// The build MUST run inside an OSS-Fuzz base-builder container (or any
// container that has clang, libstdc++ 13+, and cmake). Reason: the
// downstream OSS-Fuzz fuzzer binaries are linked against libstdc++
// (gcc-style `std::string`), but clang's default stdlib is libc++
// (`std::__cxx11::basic_string`). ABI mismatch silently produces a binary
// that links but cannot find the right string symbols at runtime. Forcing
// `-stdlib=libstdc++` inside the build container pins both sides to the
// gcc ABI.
//
// Build flow:
//  1. Copy `pfuzzer-hfc-patch/FuzzerHFC.{h,cpp}` over `pfuzzer/FuzzerHFC.{h,cpp}`
//     inside the bind-mounted submodule working tree.
//  2. Patch `pfuzzer/CMakeLists.txt` to comment out `FuzzerHFC.cpp` (the
//     original V1 file is replaced by the V2 patch above; excluding the V1
//     path avoids duplicate-symbol / stale-data conflicts).
//  3. Run cmake + make inside the OSS-Fuzz base-builder container.
//  4. Restore the patched/overlaid files via `git checkout` so the
//     submodule working tree stays clean (submodule commit hash
//     unchanged).
//
// Output: <repo>/build/v2/pfuzzer-build/libfuzzer.a (already .gitignored
// via the `build/` rule). Embedded into the OSS-Fuzz builder container at
// /opt/orchestra/pfuzzer-hfc-patch/libFuzzer.a by `internal/ossfuzz/plan.go`.
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
	outDir := flags.String("out", "build/v2/pfuzzer-build", "output directory; libfuzzer.a is written here. Default is repo-relative under build/, which .gitignore covers.")
	hfcPatchDir := flags.String("hfc-patch", "pfuzzer-hfc-patch", "directory containing V2 FuzzerHFC.h and FuzzerHFC.cpp that overlay the upstream versions in the pfuzzer submodule")
	image := flags.String("image", "gcr.io/oss-fuzz-base/base-builder:latest", "Docker image used to build pfuzzer. Must have clang, libstdc++ 13+, and cmake.")
	jobs := flags.Int("jobs", 0, "parallel build jobs inside the container (0 = nproc)")
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
	//
	// The recovered files are restored via `git checkout <path>` inside the
	// pfuzzer submodule directory, not via a backup-file rename. Reason:
	// the build container runs as root; backup files created inside
	// /pfuzzer may end up with root ownership, and a later host-side
	// rename can fail with EACCES. `git checkout` reads the committed
	// blob from the submodule's object database and writes it directly,
	// bypassing the backup file entirely.
	defer func() {
		// Restore CMakeLists.txt (FuzzerHFC.{h,cpp} are restored below).
		cmd := exec.Command("git", "checkout", "--", "CMakeLists.txt")
		cmd.Dir = pfuzzerSrc
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("warning: failed to git checkout CMakeLists.txt in %s: %v", pfuzzerSrc, err)
		}
	}()

	// Overlay the V2 HTTP client onto the submodule.
	hfcBackups := []string{}
	defer func() {
		// Restore the original FuzzerHFC.{h,cpp} from git index.
		for _, fname := range []string{"FuzzerHFC.h", "FuzzerHFC.cpp"} {
			cmd := exec.Command("git", "checkout", "--", fname)
			cmd.Dir = pfuzzerSrc
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				log.Printf("warning: failed to git checkout %s in %s: %v", fname, pfuzzerSrc, err)
			}
		}
		// Drop backup artifacts (may have root ownership from container).
		for _, backup := range hfcBackups {
			os.Remove(backup)
		}
	}()

	// Backup the originals we are about to modify. We keep local copies so
	// we can fall back to them if `git checkout` fails (e.g., detached
	// HEAD with stale index). Best effort; restoreFile failures are
	// tolerated because git checkout is the source of truth.
	origCMake := filepath.Join(pfuzzerSrc, "CMakeLists.txt")
	backupPath := origCMake + ".v2-backup"
	if err := backupFile(origCMake, backupPath); err != nil {
		log.Printf("warning: backup CMakeLists.txt: %v", err)
	}
	hfcBackups = []string{}
	for _, fname := range []string{"FuzzerHFC.h", "FuzzerHFC.cpp"} {
		src := filepath.Join(pfuzzerSrc, fname)
		backup := src + ".v2-backup"
		if err := backupFile(src, backup); err != nil {
			log.Printf("warning: backup %s: %v", src, err)
		}
		hfcBackups = append(hfcBackups, backup)
	}

	// V2 build: exclude V1-only FuzzerHFC.cpp (replaced by V2 patch).
	if err := patchCMakeListsTxt(origCMake); err != nil {
		return fmt.Errorf("patch CMakeLists.txt: %w", err)
	}

	// Overlay the V2 HTTP client onto the submodule.
	for _, fname := range []string{"FuzzerHFC.h", "FuzzerHFC.cpp"} {
		src := filepath.Join(hfcPatch, fname)
		dst := filepath.Join(pfuzzerSrc, fname)
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("overlay %s -> %s: %w", src, dst, err)
		}
	}

	// Run cmake + make inside the OSS-Fuzz base-builder container so
	// libstdc++ headers (gcc 13.x in the image) are available and the
	// produced libfuzzer.a matches the gcc ABI of the OSS-Fuzz fuzzer
	// binaries. The repo is bind-mounted read-write at /orchestra so
	// the overlay and the output directory are both reachable.
	if err := runContainerBuild(ctx, *image, pfuzzerSrc, outputDir, *jobs); err != nil {
		return fmt.Errorf("container build: %w", err)
	}

	libPath := filepath.Join(outputDir, "libfuzzer.a")
	if !fileExists(libPath) {
		return fmt.Errorf("build reported success but %s not found", libPath)
	}
	fmt.Printf("Built pfuzzer libfuzzer.a at %s\n", libPath)
	return nil
}

// runContainerBuild invokes cmake + make inside a Docker container that
// has clang, libstdc++ 13+, and cmake. We bind-mount the entire pfuzzer
// submodule working tree at /pfuzzer (overlaid with V2 FuzzerHFC patches)
// and the host output directory at /out, then write libfuzzer.a there.
func runContainerBuild(ctx context.Context, image, pfuzzerSrc, outDir string, jobs int) error {
	nJobs := jobs
	if nJobs <= 0 {
		nJobs = nproc()
	}
	buildScript := fmt.Sprintf(`set -e
rm -rf /out/* /out/.[!.]* 2>/dev/null || true
cd /pfuzzer
cmake -S /pfuzzer -B /out/build -G "Unix Makefiles" \
  -DCMAKE_CXX_FLAGS="-w -fpermissive" \
  -DCMAKE_C_FLAGS="-w" 2>&1
make -j%d -C /out/build 2>&1
cp /out/build/libfuzzer.a /out/libfuzzer.a
chmod 0644 /out/libfuzzer.a
ls -la /out/libfuzzer.a
`, nJobs)
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--platform", "linux/amd64",
		"-v", pfuzzerSrc+":/pfuzzer",
		"-v", outDir+":/out",
		image,
		"bash", "-c", buildScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// patchCMakeListsTxt excludes the V1-only FuzzerHFC.cpp file from the
// pfuzzer library source list (V2 patches FuzzerHFC.cpp via an overlay).
func patchCMakeListsTxt(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`(?m)^(  FuzzerHFC\.cpp)$`)
	patched := re.ReplaceAll(data, []byte("# $1  # excluded by orchestra-pfuzzer-build (replaced by V2 patch)"))
	return os.WriteFile(path, patched, 0o644)
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
