#!/usr/bin/env bash
set -euo pipefail

: "${ORCHESTRA_PROFILE:?ORCHESTRA_PROFILE is required}"
: "${ORCHESTRA_PRIMARY_SOURCE_DIR:?ORCHESTRA_PRIMARY_SOURCE_DIR is required}"
: "${ORCHESTRA_SOURCE_REVISION:?ORCHESTRA_SOURCE_REVISION is required}"

case "${ORCHESTRA_PRIMARY_SOURCE_DIR}" in
  /src|/src/*) ;;
  *)
    echo "ORCHESTRA_PRIMARY_SOURCE_DIR must be /src or below /src" >&2
    exit 2
    ;;
esac

# Checkout the pinned source revision. If the primary source dir is not a
# git repo (e.g. when it's /src and subdirs are the repos), skip checkout.
if [[ -d "${ORCHESTRA_PRIMARY_SOURCE_DIR}/.git" ]]; then
  if ! git -C "${ORCHESTRA_PRIMARY_SOURCE_DIR}" cat-file -e "${ORCHESTRA_SOURCE_REVISION}^{commit}" 2>/dev/null; then
    git -C "${ORCHESTRA_PRIMARY_SOURCE_DIR}" fetch --depth=1 origin "${ORCHESTRA_SOURCE_REVISION}"
  fi
  git -C "${ORCHESTRA_PRIMARY_SOURCE_DIR}" checkout --detach "${ORCHESTRA_SOURCE_REVISION}"
else
  echo "Note: ${ORCHESTRA_PRIMARY_SOURCE_DIR} is not a git repo; skipping checkout" >&2
fi

if [[ "${ORCHESTRA_PROFILE}" == "engine" ]]; then
  exec /usr/local/bin/compile
fi

if [[ "${ORCHESTRA_PROFILE}" != "semantic-canonical" ]]; then
  echo "Unsupported ORCHESTRA_PROFILE: ${ORCHESTRA_PROFILE}" >&2
  exit 2
fi

: "${ORCHESTRA_CODEQL_DB:?ORCHESTRA_CODEQL_DB is required}"
: "${ORCHESTRA_CODEQL_LANGUAGE:=cpp}"
: "${ORCHESTRA_SOURCE_ROOT:=/src}"

if [[ -e "${ORCHESTRA_CODEQL_DB}" ]]; then
  echo "Refusing to overwrite existing CodeQL database: ${ORCHESTRA_CODEQL_DB}" >&2
  exit 2
fi

CODEQL_BIN=""
for candidate in /opt/codeql/codeql /opt/codeql/codeql/codeql; do
  if [[ -x "${candidate}" ]]; then
    CODEQL_BIN="${candidate}"
    break
  fi
done
if [[ -z "${CODEQL_BIN}" ]]; then
  echo "CodeQL executable not found in mounted bundle" >&2
  exit 2
fi

# Build the Orchestra LLVM edge ID pass inside the container.
PASS_SO=""
PASS_SRC="/opt/orchestra/llvm/id-pass"
if [[ -d "${PASS_SRC}" ]]; then
  PASS_BUILD="/tmp/orchestra-pass-build"
  rm -rf "${PASS_BUILD}"
  mkdir -p "${PASS_BUILD}"
  echo "Building Orchestra edge ID pass..." >&2
  if cmake -S "${PASS_SRC}" -B "${PASS_BUILD}" >&2 2>&1 && \
     make -C "${PASS_BUILD}" -j"$(nproc)" >&2 2>&1; then
    PASS_SO="${PASS_BUILD}/OrchestraEdgeIDPass.so"
    echo "Edge ID pass built: ${PASS_SO}" >&2
  else
    echo "Warning: failed to build edge ID pass; continuing without it" >&2
  fi
fi

# Inject the pass into compiler flags so every clang invocation loads it.
# The pass writes to ORCHESTRA_EDGE_MANIFEST in append (JSONL) mode.
# The pass also inserts a weak no-op __orchestra_record_edge definition in
# each translation unit, so non-fuzzer binaries link without the runtime
# library. Fuzzer binaries get the strong definition via LIB_FUZZING_ENGINE.
if [[ -n "${PASS_SO}" ]]; then
  EDGE_FLAG="-fpass-plugin=${PASS_SO}"
  export CFLAGS="${CFLAGS:-} ${EDGE_FLAG}"
  export CXXFLAGS="${CXXFLAGS:-} ${EDGE_FLAG}"
  # Remove the manifest if it exists from a prior run.
  rm -f "${ORCHESTRA_EDGE_MANIFEST:-/dev/null}"
fi

"${CODEQL_BIN}" database init \
  --language="${ORCHESTRA_CODEQL_LANGUAGE}" \
  --source-root="${ORCHESTRA_SOURCE_ROOT}" \
  "${ORCHESTRA_CODEQL_DB}"

# The OSS-Fuzz Dockerfile sets WORKDIR to the source checkout (e.g. /src/zlib).
# compile invokes build.sh in the current directory. CodeQL's preload_tracer
# does not inherit the shell's cwd, so we wrap compile in an explicit cd.
# Some projects' build.sh use bash brace expansion to build multiple fuzzer
# targets in one ninja command. If the pinned source version doesn't have all
# targets, ninja fails on the first unknown target. We patch build.sh to
# replace brace expansion with per-target ninja calls that tolerate failures.
"${CODEQL_BIN}" database trace-command \
  --threads=0 \
  "${ORCHESTRA_CODEQL_DB}" \
  -- bash -c "cd ${ORCHESTRA_PRIMARY_SOURCE_DIR} && \
    if [ -f \$SRC/build.sh ]; then \
      sed -i 's/ninja -v -j\$(nproc) -C \$build test\/fuzzing\/hb-{shape,raster,vector,gpu,subset,repacker}-fuzzer/for t in hb-shape-fuzzer hb-raster-fuzzer hb-vector-fuzzer hb-gpu-fuzzer hb-subset-fuzzer hb-repacker-fuzzer; do ninja -v -j\$(nproc) -C \$build test\/fuzzing\/\$t 2>\/dev\/null \\|\\| true; done/' \$SRC/build.sh 2>/dev/null; \
      sed -i 's/mv \$build\/test\/fuzzing\/hb-{shape,raster,vector,gpu,subset,repacker}-fuzzer \$OUT\//for t in hb-shape-fuzzer hb-raster-fuzzer hb-vector-fuzzer hb-gpu-fuzzer hb-subset-fuzzer hb-repacker-fuzzer; do mv \$build\/test\/fuzzing\/\$t \$OUT\/ 2>\/dev\/null \\|\\| true; done/' \$SRC/build.sh 2>/dev/null; \
    fi && \
    exec /usr/local/bin/compile"

exec "${CODEQL_BIN}" database finalize \
  --threads=0 \
  "${ORCHESTRA_CODEQL_DB}"
