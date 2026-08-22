# Orchestra repository instructions

This file is the entry point for coding agents working in this repository.
The active development line is Orchestra V2. The existing implementation is
the V1 reproduction baseline and must remain usable.

## Read before changing code

Read these files in order:

1. `docs/v2/README.md` -- navigation, setup, and the short status summary.
2. `docs/v2/DESIGN.md` -- authoritative architecture, goals, and non-goals.
3. `docs/v2/CONTRACTS.md` -- semantic rules at component boundaries.
4. `docs/v2/ROADMAP.md` -- actual implementation status, milestone gates, and
   the next work items.
5. The component README nearest the code being changed.

Do not infer completion from an interface or schema alone. `ROADMAP.md` is the
authority for whether a component is implemented, prototyped, or only reserved.

## Frozen architectural decisions

- Develop V2 beside V1. Do not migrate V2 concepts into V1 packages merely to
  reuse code.
- **V2 is a passive HTTP analyzer**: V2 runs as an HTTP server (default
  `:8080`). pfuzzer is the engine execution host (multi-engine fork coordination,
  corpus management, bitmap observation). V2 never launches fuzzers directly.
  See `docs/v2/DESIGN.md` §4.5 and `docs/v2/CONTRACTS.md` §10.
- **Pfuzzer linkage required**: every OSS-Fuzz build must link against the
  prebuilt pfuzzer `libFuzzer.a` (see `third_party/pfuzzer/`), not upstream
  libFuzzer. The substitution happens via
  `LIB_FUZZING_ENGINE=/opt/pfuzzer/libFuzzer.a`. Plain libFuzzer linkage loses
  multi-engine coordination. See `docs/v2/DESIGN.md` §4.1a.
- **Trust boundary**: pfuzzer-reported bitmaps are hints. All frontier state,
  bitmap union, and scheduler decisions use SubprocessProbe-verified bitmaps
  only. See `docs/v2/CONTRACTS.md` §10.
- **Performance contract**: V2 forbids tree-sitter at runtime and libFuzzer
  merge semantics. Bitmap union is O(K), frontier evaluation is O(1).
  See `docs/v2/DESIGN.md` §5.5 and `docs/v2/CONTRACTS.md` §12.
- **HTTP API versioning**: `/v1/*` (V1) is deprecated, retained one release
  cycle with `Deprecation` HTTP header. `/v2/*` is current. Breaking changes
  increment the URL prefix; `/v3/*` would be the next migration.
- Reuse pinned upstream OSS-Fuzz project definitions. Do not add a new
  Orchestra-specific build script for each target already supported by
  OSS-Fuzz.
- CodeQL runs only while building a Program Model. It never runs in the online
  fuzzing or scheduling path.
- Runtime edge IDs come from LLVM instrumentation. CodeQL database entity IDs
  are not runtime IDs and are not stable persistent identifiers.
- A new seed is measured with the canonical probe at most once per `model_id`.
  All later coverage operations use the cached canonical bitmap.
- Only `exact` CodeQL-to-LLVM frontier mappings are schedulable. Preserve
  `ambiguous`, `unmapped`, and `unsupported` results for diagnostics; never
  guess silently.
- Validate the measurement chain before implementing Region scoring, fuzzer
  capability learning, or scheduling policy:

  `CodeQL guard -> LLVM true/false edges -> canonical seed bitmap -> Active Frontier`

- V2 online coverage must not return to per-job full-corpus `llvm-cov` replay.

## V1 boundary

Treat the existing V1 code, target scripts, and Dockerfiles as a reproduction
baseline and migration reference. In particular, do not put these back on the
V2 main path:

- Tree-sitter-based semantic inference;
- Fuzz Introspector root-to-leaf call-path Regions;
- full-corpus `llvm-cov` after every job;
- shared mutable `PrerunData`-style state;
- line-number-array coverage attribution;
- unexplained aggregate scores, random fallbacks, or hard-coded job durations;
- **V1's HTTP plugin-graph** (`internal/plugin/`, `internal/webcore/`): V2
  reuses only the process-management experience; the V1 plugin graph is
  replaced by `pfuzzer/FuzzerOrchestra.cpp` (HTTP client to `/v2/*`).
- **V1's libFuzzer integration**: V2 binaries are pfuzzer-linked, not libFuzzer-linked.

Reusing isolated process-management or corpus-discovery code is allowed only
behind a V2 adapter and with V2 contracts at the boundary.

## Current priority

The first priority is the passive-analyzer refactor (turn 12; see
`docs/v2/ROADMAP.md` T5):

1. T5.1 — HTTP API skeleton (`internal/api/`, `/v2/*` endpoints).
2. T5.2 — trust boundary (pfuzzer bitmap override via SubprocessProbe).
3. T5.3 — scheduler HTTP exposure (`Scheduler.RecommendFrontiers`,
   `Scheduler.RecordCoverageReport`).
4. T5.4 — pfuzzer HTTP client (`pfuzzer/FuzzerOrchestra.cpp`).
5. T5.5 — cleanup (`internal/pilot/` removed; `internal/worker/adapter.go`
   marked `// Optional:`).
6. T6 — pfuzzer linkage (`third_party/pfuzzer/`,
   `cmd/orchestra-pfuzzer-build`).

The configured zlib target is authoritative for the first vertical slice.
Older planning notes may mention libxml2 as an example; do not switch targets
without an explicit repository decision.

The measurement chain gates (M0–M4) remain closed: `CodeQL guard -> LLVM
true/false edges -> canonical seed bitmap -> Active Frontier` must validate
before scheduler/policy work resumes. The pfuzzer HTTP integration
(T5.4, T7) does not unlock scheduler work; it only validates the
end-to-end HTTP path.

## Change discipline

- Preserve pinned revisions. Do not replace a commit with `main`, `master`,
  `HEAD`, or another mutable reference.
- Keep commands as argument arrays when executed from Go. Do not introduce
  shell interpolation for target names, paths, or environment values.
- Do not commit the CodeQL CLI, an OSS-Fuzz checkout, generated databases,
  target binaries, corpora, or build artifacts.
- Contract changes must update the Go type, SQL/JSON schema, documentation,
  and tests together. Increment the relevant schema version for an incompatible
  change.
- Keep raw semantic facts. Do not irreversibly collapse predicate features to
  a single label in the Program Model.
- Add a focused test for every corrected invariant or regression.
- Keep unrelated V1 changes out of V2 commits.

## Verification

For Go-only V2 changes, run:

```bash
make test-v2
go vet ./cmd/orchestra-ossfuzz ./cmd/orchestra-coordinator \
  ./cmd/orchestra-model-build \
  ./internal/api ./internal/artifact ./internal/bitmap ./internal/buildconfig \
  ./internal/campaign ./internal/contracts ./internal/coordinator \
  ./internal/factexport ./internal/frontier ./internal/modelbuilder \
  ./internal/ossfuzz ./internal/probe ./internal/programmodel \
  ./internal/region ./internal/replay ./internal/scheduler ./internal/worker
make v2
```

Also run the checks relevant to the changed boundary:

- shell: `bash -n scripts/orchestra-ossfuzz-entrypoint.sh`
- SQLite: create fresh databases from both files in `schema/`
- JSON schema: validate at least one generated manifest
- CodeQL: run query compilation/golden tests against the pinned bundle
- LLVM/probe: run unit fixtures and the end-to-end two-seed test described in
  `ROADMAP.md`
- OSS-Fuzz: execute the actual builder and matching base-runner smoke test;
  command planning tests alone do not satisfy M0
- **HTTP API**: any change to `internal/api/` requires `make test-v2` plus a
  round-trip test that the endpoint returns schema-valid JSON. Pfuzzer-driven
  endpoints under `/v2/*` must use the trust-boundary semantics from
  `docs/v2/CONTRACTS.md` §10.
- **Pfuzzer linkage**: any change to `scripts/orchestra-ossfuzz-entrypoint.sh`
  or `internal/ossfuzz/plan.go` must verify that
  `LIB_FUZZING_ENGINE=/path/to/pfuzzer/libFuzzer.a` produces a binary whose
  `./binary --help` lists `-fork` and `-fuzzers`.

The full V1 test suite has a pre-existing failure in
`internal/analysis/TestParseDebugInfoFromFile` when its static debug fixture is
empty. Do not modify V1 merely to hide that failure; report it separately.

## Completion reports

When handing work back, state:

- milestone and exit criterion addressed;
- files and contracts changed;
- commands actually run and their results;
- generated artifact paths and fingerprints, when applicable;
- remaining gaps, ambiguous mappings, unsupported cases, and assumptions.

Never report a planned command, mock, interface, or schema as a successful
real-target integration.
