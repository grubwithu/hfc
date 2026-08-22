#!/usr/bin/env bash
# Launch all 20 builds in parallel (max 6 at a time), each as an independent
# background process. No wait/jobs logic — just launch and collect results.
set -uo pipefail
cd /mnt/hd/workspace/parallel_fuzz/HFC

RESULTS_DIR="/tmp/v2-final"
mkdir -p "$RESULTS_DIR"
# Clear previous results
> "$RESULTS_DIR/summary.txt"

# Define a function file for each target
build_target() {
  local target="$1"
  local proj=$(grep -A5 "id: $target$" experiments/targets.yaml | grep oss_fuzz_project | awk '{print $2}')
  local fuzz_target=$(grep -A5 "id: $target$" experiments/targets.yaml | grep fuzz_target | awk '{print $2}')
  local src_dir=$(grep -A5 "id: $target$" experiments/targets.yaml | grep primary_source_dir | awk '{print $2}')
  local src_rev=$(grep -A5 "id: $target$" experiments/targets.yaml | grep source_revision | awk '{print $2}')
  local lang=$(grep -A5 "id: $target$" experiments/targets.yaml | grep "language:" | awk '{print $2}')
  local REPO_ROOT="/mnt/hd/workspace/parallel_fuzz/HFC"
  local CODEQL="$REPO_ROOT/tools/codeql"
  local ART_DIR="$REPO_ROOT/build/v2/artifacts/$target/semantic-canonical"
  local LOG="$RESULTS_DIR/$target.log"

  sudo rm -rf "$REPO_ROOT/build/v2/artifacts/$target" 2>/dev/null
  mkdir -p "$ART_DIR/out" "$ART_DIR/work"

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
  local RC=$?
  sudo chown -R grub:grub "$ART_DIR" 2>/dev/null

  if [ $RC -ne 0 ]; then
    local err=$(tail -2 "$LOG" | tr '\n' ' ' | head -c 200)
    echo "✗ $target|BUILD FAIL(rc=$RC)|$err" > "$RESULTS_DIR/result-$target.txt"
    return
  fi

  # Find binary
  local binary="$ART_DIR/out/$fuzz_target"
  if [ ! -f "$binary" ]; then
    local found=$(find "$ART_DIR/out/" -maxdepth 1 -type f -executable ! -name "llvm-symbolizer" 2>/dev/null | head -1)
    if [ -n "$found" ]; then
      binary="$found"
      fuzz_target=$(basename "$found")
    else
      echo "✗ $target|NO BINARY" > "$RESULTS_DIR/result-$target.txt"
      return
    fi
  fi

  # Check CodeQL DB
  if [ ! -d "$ART_DIR/work/codeql-db" ]; then
    echo "✗ $target|NO CODEQL DB" > "$RESULTS_DIR/result-$target.txt"
    return
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
    echo "✗ $target|SMOKE FAIL(rc=$SMOKE_RC)|bin=$fuzz_target edges=$EDGE_COUNT" > "$RESULTS_DIR/result-$target.txt"
  else
    echo "✓ $target|OK|bin=$fuzz_target edges=$EDGE_COUNT" > "$RESULTS_DIR/result-$target.txt"
  fi
}

# Export the function so we can call it in subshells
export -f build_target

TARGETS=(bloaty curl freetype2 harfbuzz jsoncpp lcms libjpeg-turbo libpcap libpng libxml2 libxslt mbedtls openssl openthread proj4 re2 sqlite3 systemd vorbis woff2)
MAX=6
running=0

for target in "${TARGETS[@]}"; do
  # Throttle: wait if too many running
  while [ $running -ge $MAX ]; do
    sleep 10
    running=0
    for t in "${TARGETS[@]}"; do
      [ -f "$RESULTS_DIR/result-$t.txt" ] && continue
      # Check if a docker build for this target is still running
      docker ps --format '{{.Image}}' 2>/dev/null | grep -q "oss-fuzz/$(grep -A5 "id: $t$" experiments/targets.yaml | grep oss_fuzz_project | awk '{print $2}')" && running=$((running+1))
    done
  done
  echo "Launching: $target"
  bash -c "build_target '$target'" &
  running=$((running+1))
  sleep 3  # Stagger launches
done

echo "All targets launched. Waiting for completion..."
