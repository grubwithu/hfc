#!/usr/bin/env bash
# Parallel build verification for all V2 targets.
# Runs up to N builds concurrently, each in its own Docker container.
set -uo pipefail
cd /mnt/hd/workspace/parallel_fuzz/HFC

TARGETS=(bloaty curl freetype2 harfbuzz jsoncpp lcms libjpeg-turbo libpcap libpng libxml2 libxslt mbedtls openssl openthread proj4 re2 sqlite3 systemd vorbis woff2)
REPO_ROOT=$(pwd)
CODEQL="$REPO_ROOT/tools/codeql"
MAX_PARALLEL=4
RESULTS_DIR="/tmp/v2-results"
mkdir -p "$RESULTS_DIR"
> "$RESULTS_DIR/summary.txt"

build_one() {
  local target="$1"
  local proj=$(grep -A5 "id: $target$" experiments/targets.yaml | grep oss_fuzz_project | awk '{print $2}')
  local fuzz_target=$(grep -A5 "id: $target$" experiments/targets.yaml | grep fuzz_target | awk '{print $2}')
  local src_dir=$(grep -A5 "id: $target$" experiments/targets.yaml | grep primary_source_dir | awk '{print $2}')
  local src_rev=$(grep -A5 "id: $target$" experiments/targets.yaml | grep source_revision | awk '{print $2}')
  local lang=$(grep -A5 "id: $target$" experiments/targets.yaml | grep "language:" | awk '{print $2}')

  local ART_DIR="$REPO_ROOT/build/v2/artifacts/$target/semantic-canonical"
  sudo rm -rf "$REPO_ROOT/build/v2/artifacts/$target" 2>/dev/null
  mkdir -p "$ART_DIR/out" "$ART_DIR/work"

  local LOG="$RESULTS_DIR/build-$target.log"

  # Build
  timeout 600 docker run --privileged --shm-size=2g --platform linux/amd64 --rm \
    -e "FUZZING_ENGINE=libfuzzer" -e "SANITIZER=address" -e "ARCHITECTURE=x86_64" \
    -e "PROJECT_NAME=$proj" -e "FUZZING_LANGUAGE=$lang" -e "HELPER=True" \
    -e "ORCHESTRA_PROFILE=semantic-canonical" \
    -e "ORCHESTRA_PRIMARY_SOURCE_DIR=$src_dir" \
    -e "ORCHESTRA_SOURCE_REVISION=$src_rev" \
    -e "http_proxy=http://172.17.0.1:3128" -e "https_proxy=http://172.17.0.1:3128" \
    -e "HTTP_PROXY=http://172.17.0.1:3128" -e "HTTPS_PROXY=http://172.17.0.1:3128" \
    -v "$ART_DIR/out:/out" -v "$ART_DIR/work:/work" \
    -v "$REPO_ROOT:/opt/orchestra:ro" \
    --entrypoint /opt/orchestra/scripts/orchestra-ossfuzz-entrypoint.sh \
    -e "ORCHESTRA_CODEQL_DB=/work/codeql-db" -e "ORCHESTRA_CODEQL_LANGUAGE=cpp" \
    -e "ORCHESTRA_SOURCE_ROOT=/src" \
    -v "$CODEQL:/opt/codeql:ro" \
    -e "ORCHESTRA_EDGE_MANIFEST=/out/orchestra-edge-manifest.jsonl" \
    "gcr.io/oss-fuzz/$proj" > "$LOG" 2>&1
  local BUILD_RC=$?
  sudo chown -R grub:grub "$ART_DIR" 2>/dev/null

  if [ $BUILD_RC -ne 0 ]; then
    echo "✗ $target: BUILD FAILED (rc=$BUILD_RC)" >> "$RESULTS_DIR/summary.txt"
    return 1
  fi

  # Check binary
  if [ ! -f "$ART_DIR/out/$fuzz_target" ]; then
    echo "✗ $target: BINARY NOT FOUND ($fuzz_target)" >> "$RESULTS_DIR/summary.txt"
    return 1
  fi

  # Check CodeQL DB
  if [ ! -d "$ART_DIR/work/codeql-db" ]; then
    echo "✗ $target: CODEQL DB MISSING" >> "$RESULTS_DIR/summary.txt"
    return 1
  fi

  local EDGE_COUNT=0
  if [ -f "$ART_DIR/out/orchestra-edge-manifest.jsonl" ]; then
    EDGE_COUNT=$(wc -l < "$ART_DIR/out/orchestra-edge-manifest.jsonl")
  fi

  # Smoke test
  local RUNNER_IMAGE="gcr.io/oss-fuzz-base/base-runner"
  local FROM_LINE=$(grep "^FROM" "third_party/oss-fuzz/projects/$proj/Dockerfile" 2>/dev/null | head -1)
  if echo "$FROM_LINE" | grep -q "base-builder:"; then
    local TAG=$(echo "$FROM_LINE" | sed 's/.*base-builder://')
    RUNNER_IMAGE="gcr.io/oss-fuzz-base/base-runner:$TAG"
  fi

  timeout 60 docker run --platform linux/amd64 --rm \
    -e "FUZZING_ENGINE=libfuzzer" -e "SANITIZER=address" -e "ARCHITECTURE=x86_64" \
    -e "FUZZING_LANGUAGE=$lang" -e "HELPER=True" \
    -v "$ART_DIR/out:/out" \
    "$RUNNER_IMAGE" test_one.py "$fuzz_target" > "$RESULTS_DIR/smoke-$target.log" 2>&1
  local SMOKE_RC=$?

  if [ $SMOKE_RC -ne 0 ]; then
    echo "✗ $target: SMOKE TEST FAILED (rc=$SMOKE_RC)" >> "$RESULTS_DIR/summary.txt"
    return 1
  fi

  echo "✓ $target: BUILD+SMOKE OK (edges=$EDGE_COUNT)" >> "$RESULTS_DIR/summary.txt"
  return 0
}

export -f build_one
export REPO_ROOT CODEQL RESULTS_DIR

echo "Starting parallel builds ($MAX_PARALLEL at a time)..."
echo ""

# Launch all builds in parallel with a concurrency limit
pids=()
running=0
for target in "${TARGETS[@]}"; do
  while [ $running -ge $MAX_PARALLEL ]; do
    wait -n 2>/dev/null || sleep 5
    running=0
    for pid in "${pids[@]}"; do
      kill -0 "$pid" 2>/dev/null && running=$((running+1))
    done
  done
  echo "  Launching: $target"
  build_one "$target" &
  pids+=($!)
  running=$((running+1))
done

# Wait for all
echo "Waiting for all builds to complete..."
wait

echo ""
echo "=========================================="
echo "FINAL RESULTS"
echo "=========================================="
cat "$RESULTS_DIR/summary.txt" | sort
echo ""
PASS=$(grep -c '✓' "$RESULTS_DIR/summary.txt")
FAIL=$(grep -c '✗' "$RESULTS_DIR/summary.txt")
echo "Passed: $PASS / $((PASS+FAIL))"
echo "Failed: $FAIL / $((PASS+FAIL))"
