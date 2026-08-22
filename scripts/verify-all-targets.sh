#!/usr/bin/env bash
# Verify build correctness and artifact validity for each V2 target.
# Runs the semantic-canonical Docker build and checks for binary + manifest.
set -uo pipefail
cd /mnt/hd/workspace/parallel_fuzz/HFC

TARGETS=(bloaty curl freetype2 harfbuzz jsoncpp lcms libjpeg-turbo libpcap libpng libxml2 libxslt mbedtls openssl openthread proj4 re2 sqlite3 systemd vorbis woff2)
REPO_ROOT=$(pwd)
CODEQL="$REPO_ROOT/tools/codeql"
PASS=0
FAIL=0
RESULTS_FILE="/tmp/v2-build-results.txt"
> "$RESULTS_FILE"

for target in "${TARGETS[@]}"; do
  echo ""
  echo "=========================================="
  echo "TARGET: $target"
  echo "=========================================="

  # Read target config
  proj=$(grep -A5 "id: $target$" experiments/targets.yaml | grep oss_fuzz_project | awk '{print $2}')
  fuzz_target=$(grep -A5 "id: $target$" experiments/targets.yaml | grep fuzz_target | awk '{print $2}')
  src_dir=$(grep -A5 "id: $target$" experiments/targets.yaml | grep primary_source_dir | awk '{print $2}')
  src_rev=$(grep -A5 "id: $target$" experiments/targets.yaml | grep source_revision | awk '{print $2}')
  lang=$(grep -A5 "id: $target$" experiments/targets.yaml | grep "language:" | awk '{print $2}')

  # Clean previous artifacts
  sudo rm -rf "build/v2/artifacts/$target" 2>/dev/null
  ART_DIR="$REPO_ROOT/build/v2/artifacts/$target/semantic-canonical"
  mkdir -p "$ART_DIR/out" "$ART_DIR/work"

  # Run the semantic-canonical build directly via Docker
  LOG="/tmp/build-$target.log"
  timeout 600 docker run --privileged --shm-size=2g --platform linux/amd64 --rm \
    -e "FUZZING_ENGINE=libfuzzer" -e "SANITIZER=address" -e "ARCHITECTURE=x86_64" \
    -e "PROJECT_NAME=$proj" -e "FUZZING_LANGUAGE=$lang" -e "HELPER=True" \
    -e "ORCHESTRA_PROFILE=semantic-canonical" \
    -e "ORCHESTRA_PRIMARY_SOURCE_DIR=$src_dir" \
    -e "ORCHESTRA_SOURCE_REVISION=$src_rev" \
    -e "http_proxy=http://172.17.0.1:3128" \
    -e "https_proxy=http://172.17.0.1:3128" \
    -e "HTTP_PROXY=http://172.17.0.1:3128" \
    -e "HTTPS_PROXY=http://172.17.0.1:3128" \
    -v "$ART_DIR/out:/out" -v "$ART_DIR/work:/work" \
    -v "$REPO_ROOT:/opt/orchestra:ro" \
    --entrypoint /opt/orchestra/scripts/orchestra-ossfuzz-entrypoint.sh \
    -e "ORCHESTRA_CODEQL_DB=/work/codeql-db" -e "ORCHESTRA_CODEQL_LANGUAGE=cpp" \
    -e "ORCHESTRA_SOURCE_ROOT=/src" \
    -v "$CODEQL:/opt/codeql:ro" \
    -e "ORCHESTRA_EDGE_MANIFEST=/out/orchestra-edge-manifest.jsonl" \
    "gcr.io/oss-fuzz/$proj" > "$LOG" 2>&1
  BUILD_RC=$?

  # Fix ownership
  sudo chown -R grub:grub "$ART_DIR" 2>/dev/null

  if [ $BUILD_RC -ne 0 ]; then
    echo "BUILD FAILED (rc=$BUILD_RC)"
    tail -5 "$LOG"
    echo "✗ $target: BUILD FAILED" >> "$RESULTS_FILE"
    FAIL=$((FAIL+1))
    continue
  fi

  # Check if binary exists
  BINARY="$ART_DIR/out/$fuzz_target"
  if [ ! -f "$BINARY" ]; then
    echo "BINARY NOT FOUND: $BINARY"
    echo "Available files in /out:"
    ls "$ART_DIR/out/" 2>/dev/null | head -10
    echo "✗ $target: BINARY NOT FOUND ($fuzz_target)" >> "$RESULTS_FILE"
    FAIL=$((FAIL+1))
    continue
  fi

  # Check if CodeQL DB exists
  if [ ! -d "$ART_DIR/work/codeql-db" ]; then
    echo "CODEQL DB NOT FOUND"
    echo "✗ $target: CODEQL DB MISSING" >> "$RESULTS_FILE"
    FAIL=$((FAIL+1))
    continue
  fi

  # Check if edge manifest exists
  MANIFEST="$ART_DIR/out/orchestra-edge-manifest.jsonl"
  if [ -f "$MANIFEST" ]; then
    EDGE_COUNT=$(wc -l < "$MANIFEST")
  else
    EDGE_COUNT=0
  fi

  # Run smoke test via base-runner
  RUNNER_IMAGE="gcr.io/oss-fuzz-base/base-runner"
  # Check if Dockerfile uses a tagged base-builder
  FROM_LINE=$(grep "^FROM" "third_party/oss-fuzz/projects/$proj/Dockerfile" 2>/dev/null | head -1)
  if echo "$FROM_LINE" | grep -q "base-builder:"; then
    TAG=$(echo "$FROM_LINE" | sed 's/.*base-builder://')
    RUNNER_IMAGE="gcr.io/oss-fuzz-base/base-runner:$TAG"
  fi

  timeout 60 docker run --platform linux/amd64 --rm \
    -e "FUZZING_ENGINE=libfuzzer" -e "SANITIZER=address" -e "ARCHITECTURE=x86_64" \
    -e "FUZZING_LANGUAGE=$lang" -e "HELPER=True" \
    -v "$ART_DIR/out:/out" \
    "$RUNNER_IMAGE" test_one.py "$fuzz_target" > /tmp/smoke-$target.log 2>&1
  SMOKE_RC=$?

  if [ $SMOKE_RC -ne 0 ]; then
    echo "SMOKE TEST FAILED (rc=$SMOKE_RC)"
    tail -5 /tmp/smoke-$target.log
    echo "✗ $target: SMOKE TEST FAILED" >> "$RESULTS_FILE"
    FAIL=$((FAIL+1))
    continue
  fi

  echo "✓ BUILD OK, BINARY OK, CODEQL DB OK, edges=$EDGE_COUNT, SMOKE OK"
  echo "✓ $target: BUILD+SMOKE OK (edges=$EDGE_COUNT)" >> "$RESULTS_FILE"
  PASS=$((PASS+1))
done

echo ""
echo "=========================================="
echo "FINAL RESULTS"
echo "=========================================="
cat "$RESULTS_FILE"
echo ""
echo "Passed: $PASS / $((PASS+FAIL))"
echo "Failed: $FAIL / $((PASS+FAIL))"
