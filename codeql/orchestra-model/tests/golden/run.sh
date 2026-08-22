#!/usr/bin/env bash
# Golden fixture test for the Orchestra CodeQL QL pack.
#
# Builds a CodeQL database from a small C file with known facts, runs the
# orchestra-model queries, and checks that function/call/guard counts and
# key entities match expected values.
#
# Usage: tests/golden/run.sh /path/to/codeql/binary
set -euo pipefail

CODEQL_BIN="${1:?usage: $0 <codeql-binary>}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
DB="${ROOT}/.codeql-db"
RESULTS="${ROOT}/.results"

# Clean any previous run.
rm -rf "${DB}" "${RESULTS}"

# Build the database.
"${CODEQL_BIN}" database create \
  --language=cpp \
  --source-root="${ROOT}" \
  --overwrite \
  --command="clang -c -fsyntax-only -I${ROOT} ${ROOT}/guards.c" \
  "${DB}"

# Run the QL pack queries.
"${CODEQL_BIN}" database run-queries \
  --threads=0 \
  -- "${DB}" "${ROOT}/../../"

# Decode results to CSV.
mkdir -p "${RESULTS}"
"${CODEQL_BIN}" bqrs decode --format=csv \
  "${DB}/results/grubwithu/orchestra-model/src/Functions.bqrs" \
  > "${RESULTS}/functions.csv"
"${CODEQL_BIN}" bqrs decode --format=csv \
  "${DB}/results/grubwithu/orchestra-model/src/Calls.bqrs" \
  > "${RESULTS}/calls.csv"
"${CODEQL_BIN}" bqrs decode --format=csv \
  "${DB}/results/grubwithu/orchestra-model/src/Guards.bqrs" \
  > "${RESULTS}/guards.csv"

# --- Assertions ---

# Functions: expect 6 (check_signed, check_unsigned, check_magic,
# check_length, helper, LLVMFuzzerTestOneInput)
FUNC_COUNT=$(($(wc -l < "${RESULTS}/functions.csv") - 1))
if [[ "${FUNC_COUNT}" -ne 6 ]]; then
  echo "FAIL: expected 6 functions, got ${FUNC_COUNT}"
  cat "${RESULTS}/functions.csv"
  exit 1
fi
echo "OK: ${FUNC_COUNT} functions"

# Each expected function name must appear.
for name in check_signed check_unsigned check_magic check_length helper LLVMFuzzerTestOneInput; do
  if ! grep -q "\"${name}\"" "${RESULTS}/functions.csv"; then
    echo "FAIL: function ${name} not found"
    cat "${RESULTS}/functions.csv"
    exit 1
  fi
done
echo "OK: all expected function names present"

# Calls: expect at least 8 direct calls (4 from LLVMFuzzerTestOneInput + 4 from check_*)
CALL_COUNT=$(($(wc -l < "${RESULTS}/calls.csv") - 1))
if [[ "${CALL_COUNT}" -lt 8 ]]; then
  echo "FAIL: expected >= 8 calls, got ${CALL_COUNT}"
  cat "${RESULTS}/calls.csv"
  exit 1
fi
echo "OK: ${CALL_COUNT} direct calls"

# Guards: expect 5 if-guards (one in each check_* + one in LLVMFuzzerTestOneInput)
GUARD_COUNT=$(($(wc -l < "${RESULTS}/guards.csv") - 1))
if [[ "${GUARD_COUNT}" -ne 5 ]]; then
  echo "FAIL: expected 5 guards, got ${GUARD_COUNT}"
  cat "${RESULTS}/guards.csv"
  exit 1
fi
echo "OK: ${GUARD_COUNT} guards"

# Guard in check_length has a short-circuit (&&). Verify it is captured.
if ! grep -q "len" "${RESULTS}/guards.csv"; then
  echo "FAIL: expected guard with 'len' variable not found"
  cat "${RESULTS}/guards.csv"
  exit 1
fi
echo "OK: guard with length check present"

echo ""
echo "All golden fixture assertions passed."
rm -rf "${DB}" "${RESULTS}"
