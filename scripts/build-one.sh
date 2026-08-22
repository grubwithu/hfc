#!/usr/bin/env bash
# Simple per-target build+verify script. Each target gets its own script file.
# Usage: ./build-one.sh <target>
set -euo pipefail
cd /mnt/hd/workspace/parallel_fuzz/HFC

TARGET="$1"
PROJ=$(grep -A5 "id: $TARGET$" experiments/targets.yaml | grep oss_fuzz_project | awk '{print $2}')
FUZZ_TARGET=$(grep -A5 "id: $TARGET$" experiments/targets.yaml | grep fuzz_target | awk '{print $2}')
SRC_DIR=$(grep -A5 "id: $TARGET$" experiments/targets.yaml | grep primary_source_dir | awk '{print $2}')
SRC_REV=$(grep -A5 "id: $TARGET$" experiments/targets.yaml | grep source_revision | awk '{print $2}')
LANG=$(grep -A5 "id: $TARGET$" experiments/targets.yaml | grep "language:" | awk '{print $2}')
REPO_ROOT=$(pwd)
CODEQL="$REPO_ROOT/tools/codeql"
RESULTS_DIR="/tmp/v2-final"
ART_DIR="$REPO_ROOT/build/v2/artifacts/$TARGET/semantic-canonical"

mkdir -p "$RESULTS_DIR"
sudo rm -rf "$REPO_ROOT/build/v2/artifacts/$TARGET" 2>/dev/null
mkdir -p "$ART_DIR/out" "$ART_DIR/work"

# Build
timeout 600 docker run --privileged --shm-size=2g --platform linux/amd64 --rm \
  -e "FUZZING_ENGINE=libfuzzer" -e "SANITIZER=address" -e "ARCHITECTURE=x86_64" \
  -e "PROJECT_NAME=$PROJ" -e "FUZZING_LANGUAGE=$LANG" -e "HELPER=True" \
  -e "ORCHESTRA_PROFILE=semantic-canonical" \
  -e "ORCHESTRA_PRIMARY_SOURCE_DIR=$SRC_DIR" \
  -e "ORCHESTRA_SOURCE_REVISION=$SRC_REV" \
  -e "http_proxy=http://172.17.0.1:3128" -e "https_proxy=http://172.17.0.1:3128" \
  -e "HTTP_PROXY=http://172.17.0.1:3128" -e "HTTPS_PROXY=http://172.17.0.1:3128" \
  -v "$ART_DIR/out:/out" -v "$ART_DIR/work:/work" \
  -v "$REPO_ROOT:/opt/orchestra:ro" \
  --entrypoint /opt/orchestra/scripts/orchestra-ossfuzz-entrypoint.sh \
  -e "ORCHESTRA_CODEQL_DB=/work/codeql-db" -e "ORCHESTRA_CODEQL_LANGUAGE=cpp" \
  -e "ORCHESTRA_SOURCE_ROOT=/src" \
  -v "$CODEQL:/opt/codeql:ro" \
  -e "ORCHESTRA_EDGE_MANIFEST=/out/orchestra-edge-manifest.jsonl" \
  "gcr.io/oss-fuzz/$PROJ" > "$RESULTS_DIR/$TARGET.log" 2>&1
RC=$?
sudo chown -R grub:grub "$ART_DIR" 2>/dev/null

if [ $RC -ne 0 ]; then
  ERR=$(tail -2 "$RESULTS_DIR/$TARGET.log" | tr '\n' ' ' | head -c 200)
  echo "✗ $TARGET|BUILD FAIL(rc=$RC)|$ERR" > "$RESULTS_DIR/result-$TARGET.txt"
  exit 0
fi

# Find binary
BINARY="$ART_DIR/out/$FUZZ_TARGET"
if [ ! -f "$BINARY" ]; then
  FOUND=$(find "$ART_DIR/out/" -maxdepth 1 -type f -executable ! -name "llvm-symbolizer" 2>/dev/null | head -1)
  if [ -n "$FOUND" ]; then
    BINARY="$FOUND"
    FUZZ_TARGET=$(basename "$FOUND")
  else
    echo "✗ $TARGET|NO BINARY" > "$RESULTS_DIR/result-$TARGET.txt"
    exit 0
  fi
fi

# Check CodeQL DB
if [ ! -d "$ART_DIR/work/codeql-db" ]; then
  echo "✗ $TARGET|NO CODEQL DB" > "$RESULTS_DIR/result-$TARGET.txt"
  exit 0
fi

EDGE_COUNT=0
if [ -f "$ART_DIR/out/orchestra-edge-manifest.jsonl" ]; then
  EDGE_COUNT=$(wc -l < "$ART_DIR/out/orchestra-edge-manifest.jsonl")
fi

# Smoke test
RUNNER_IMAGE="gcr.io/oss-fuzz-base/base-runner"
FROM_LINE=$(grep "^FROM" "third_party/oss-fuzz/projects/$PROJ/Dockerfile" 2>/dev/null | head -1)
if echo "$FROM_LINE" | grep -q "base-builder:"; then
  TAG=$(echo "$FROM_LINE" | sed 's/.*base-builder://')
  RUNNER_IMAGE="gcr.io/oss-fuzz-base/base-runner:$TAG"
fi

timeout 60 docker run --platform linux/amd64 --rm \
  -e "FUZZING_ENGINE=libfuzzer" -e "SANITIZER=address" -e "ARCHITECTURE=x86_64" \
  -e "FUZZING_LANGUAGE=$LANG" -e "HELPER=True" \
  -v "$ART_DIR/out:/out" \
  "$RUNNER_IMAGE" test_one.py "$FUZZ_TARGET" > "$RESULTS_DIR/smoke-$TARGET.log" 2>&1
SMOKE_RC=$?

if [ $SMOKE_RC -ne 0 ]; then
  echo "✗ $TARGET|SMOKE FAIL(rc=$SMOKE_RC)|bin=$FUZZ_TARGET edges=$EDGE_COUNT" > "$RESULTS_DIR/result-$TARGET.txt"
else
  echo "✓ $TARGET|OK|bin=$FUZZ_TARGET edges=$EDGE_COUNT" > "$RESULTS_DIR/result-$TARGET.txt"
fi
