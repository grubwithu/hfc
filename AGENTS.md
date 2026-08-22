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

- Different fuzzing engines may require separate builds. The requirement is
  one reusable OSS-Fuzz project definition, not one binary for all engines.
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
- unexplained aggregate scores, random fallbacks, or hard-coded job durations.

Reusing isolated process-management or corpus-discovery code is allowed only
behind a V2 adapter and with V2 contracts at the boundary.

## Current priority

The first priority is M0 in `docs/v2/ROADMAP.md`: run the pinned
`zlib-uncompress` target through a real OSS-Fuzz semantic-canonical build,
produce and inspect its artifact manifest and CodeQL database, and record a
reproducible smoke test. Do not start the scheduler while M0-M3 gates are open.

The configured zlib target is authoritative for the first vertical slice.
Older planning notes may mention libxml2 as an example; do not switch targets
without an explicit repository decision.

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
  ./internal/artifact ./internal/bitmap ./internal/buildconfig \
  ./internal/contracts ./internal/coordinator ./internal/factexport \
  ./internal/frontier ./internal/modelbuilder ./internal/ossfuzz \
  ./internal/probe ./internal/programmodel ./internal/worker
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
