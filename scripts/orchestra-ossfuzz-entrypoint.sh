#!/usr/bin/env bash
set -euo pipefail

: "${ORCHESTRA_PROFILE:?ORCHESTRA_PROFILE is required}"
: "${ORCHESTRA_PRIMARY_SOURCE_DIR:?ORCHESTRA_PRIMARY_SOURCE_DIR is required}"
: "${ORCHESTRA_SOURCE_REVISION:?ORCHESTRA_SOURCE_REVISION is required}"

case "${ORCHESTRA_PRIMARY_SOURCE_DIR}" in
  /src/*) ;;
  *)
    echo "ORCHESTRA_PRIMARY_SOURCE_DIR must be below /src" >&2
    exit 2
    ;;
esac

if [[ ! -d "${ORCHESTRA_PRIMARY_SOURCE_DIR}/.git" ]]; then
  echo "Primary source is not a Git checkout: ${ORCHESTRA_PRIMARY_SOURCE_DIR}" >&2
  exit 2
fi

if ! git -C "${ORCHESTRA_PRIMARY_SOURCE_DIR}" cat-file -e "${ORCHESTRA_SOURCE_REVISION}^{commit}" 2>/dev/null; then
  git -C "${ORCHESTRA_PRIMARY_SOURCE_DIR}" fetch --depth=1 origin "${ORCHESTRA_SOURCE_REVISION}"
fi
git -C "${ORCHESTRA_PRIMARY_SOURCE_DIR}" checkout --detach "${ORCHESTRA_SOURCE_REVISION}"

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

exec "${CODEQL_BIN}" database create "${ORCHESTRA_CODEQL_DB}" \
  --language="${ORCHESTRA_CODEQL_LANGUAGE}" \
  --source-root="${ORCHESTRA_SOURCE_ROOT}" \
  --working-dir=/src \
  --threads=0 \
  --command=/usr/local/bin/compile
