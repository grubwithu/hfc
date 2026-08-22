#!/usr/bin/env bash
# Batch build all V2 targets through Orchestra's semantic-canonical profile.
# Reports success/failure for each target.
set -uo pipefail

cd /mnt/hd/workspace/parallel_fuzz/HFC

TARGETS=(bloaty curl freetype2 harfbuzz jsoncpp lcms libjpeg-turbo libpcap libpng libxml2 libxslt mbedtls openssl openthread proj4 re2 sqlite3 systemd vorbis woff2)
RESULTS=()
PASS=0
FAIL=0

for target in "${TARGETS[@]}"; do
  echo "=========================================="
  echo "BUILD: $target"
  echo "=========================================="
  
  # Clean any previous artifacts
  sudo rm -rf "build/v2/artifacts/$target/semantic-canonical/work/codeql-db" 2>/dev/null
  rm -rf "build/v2/artifacts/$target/semantic-canonical/out" 2>/dev/null
  
  if go run ./cmd/orchestra-ossfuzz build \
    -config experiments/targets.yaml \
    -target "$target" \
    -profiles semantic-canonical 2>&1 | tail -5; then
    RESULTS+=("✓ $target")
    PASS=$((PASS+1))
  else
    RESULTS+=("✗ $target")
    FAIL=$((FAIL+1))
    # Clean up partial build
    sudo rm -rf "build/v2/artifacts/$target/semantic-canonical/work/codeql-db" 2>/dev/null
  fi
  
  # Fix ownership
  sudo chown -R grub:grub "build/v2/artifacts/$target/" 2>/dev/null
  
  echo ""
done

echo ""
echo "=========================================="
echo "BATCH BUILD RESULTS"
echo "=========================================="
for r in "${RESULTS[@]}"; do
  echo "  $r"
done
echo ""
echo "Passed: $PASS / $((PASS+FAIL))"
echo "Failed: $FAIL / $((PASS+FAIL))"
