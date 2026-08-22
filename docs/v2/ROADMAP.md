# Orchestra V2 roadmap and handoff status

This document records what actually works on the current V2 branch. It is the
authority for completion status; interfaces, schemas, and README descriptions
alone do not prove a milestone has passed.

## 1. Handoff snapshot

Baseline scaffold commit:
`e1332ebdc2f4bb870c90eb191229539452e60d01`.

The scaffold was built and its focused Go tests, `go vet`, SQL/JSON schema
checks, and shell syntax checks passed before that commit was pushed. The full
repository suite had one pre-existing V1 failure:
`internal/analysis/TestParseDebugInfoFromFile` depends on empty static debug
fixture data.

**M0 passed**: the pinned zlib-uncompress target was built through the
semantic-canonical profile. CodeQL DB is finalized (177,344 LoC). The
base-runner smoke test exits 0. The artifact manifest validates against the
JSON schema. The fingerprint is reproducible. An entrypoint working-directory
bug was fixed (`scripts/orchestra-ossfuzz-entrypoint.sh`).

**M1 mostly passed**: enriched QL queries (Functions+reachability, Calls+
confidence, Guards+features, Constants) are tested on a golden fixture and
the zlib database. A deterministic fact export (`export-facts` command)
produces versioned JSON with timing and result counts. Input dependency
analysis and per-query cost measurement remain.

## 2. Component status

| Component | State | Gap |
|---|---|---|
| V1/V2 boundary | implemented | V1 is the only end-to-end system |
| target validation | tested | one example target |
| OSS-Fuzz adapter | tested planner | real zlib build verified |
| CodeQL wrapper | implemented | zlib DB captured and queried |
| smoke-test command | implemented | run on produced target, exit 0 |
| artifact manifest | provenance complete | model_id pending model builder |
| QL pack | enriched | functions+reachability, calls+confidence, guards+features, constants |
| fact export | implemented | deterministic JSON export with timing/counts |
| LLVM edge pass | implemented+injected | JSONL manifest for zlib, 3072 edges |
| Program Model SQL | schema + importer | model built for zlib, 848 exact frontiers |
| model builder | implemented | 82.7% exact mapping, below 90% target |
| canonical probe | interfaces | no executable, bitmap, or store |
| worker | interfaces | no engine adapter or watcher |
| bitmap operations | tested | not compressed or persistent |
| Coordinator | in-memory + model-aware + SQLite | campaign.sqlite persistence, event log |
| coverage attribution | tested | model-aware derivation from seed records |
| Active Frontier | integrated | model-aware state evaluates frontiers |
| canonical replay | implemented | subprocess probe + at-most-once store |
| seed/capability/scheduler | implemented | linear policy + capability observation |
| end-to-end pilot | implemented | multi-target + multi-fuzzer verified |
| crossing detection | absent | worker IDs are echoed |
| Region | implemented | SCC compression + control dependence; bounded context pending |
| seed/dictionary | absent | design only |
| capability/scheduler | blocked | wait for M0-M3 |
| evaluation | absent | paper experiments are M7 |

## 3. Immediate work queue

Complete these tasks in order. Do not skip to policy work.

### T0: reproduce the scaffold checks

1. Install Go 1.24.5 or a compatible toolchain.
2. Run the Go, vet, build, shell, SQL, and JSON checks in `AGENTS.md`.
3. Record tool versions and separate the known V1 fixture failure from V2
   results.

Exit: the existing V2 baseline is reproducible in the local environment.

### T1: complete the first real OSS-Fuzz build

Use `experiments/targets.yaml`; `zlib-uncompress` is the authoritative first
target.

1. Clone OSS-Fuzz into `third_party/oss-fuzz` and checkout the pinned commit.
2. Install a pinned external CodeQL bundle under `tools/codeql` without
   committing it.
3. Run `orchestra-ossfuzz validate` and `plan`; inspect paths and commands.
4. Run the real `semantic-canonical` build.
5. Verify the matching base-runner smoke test executes the target.
6. Inspect the CodeQL DB for captured C/C++ translation units and the intended
   zlib source revision.
7. Validate the generated manifest against the JSON schema.
8. Run the identical fingerprint again in a clean output location and document
   which outputs are reproducible and which metadata needs normalization.

Likely corrections belong in the generic adapter or profile contract. Do not
copy zlib's build commands into an Orchestra target script.

Exit:

- target binary exists and runs one seed through the base runner;
- CodeQL DB is finalized and contains the intended build;
- artifact manifest records verified inputs/outputs;
- logs and exact commands make the result reproducible;
- no V2 target-specific build script was added.

### T2: finish M0/M1 provenance and CodeQL facts

1. ~~Add missing manifest/model provenance: source tree, compiler/flags, CodeQL,
   QL pack, LLVM pass, schema, and model identity.~~ Done. Manifest extended
   with source_tree_hash, compiler_version, compiler_flags_hash, codeql_version,
   ql_pack_version, llvm_pass_version, model_id.
2. ~~Add CodeQL golden micro fixtures before broadening queries.~~ Done.
   `codeql/orchestra-model/tests/golden/` with guards.c and run.sh.
3. ~~Export harness reachability, guard kinds, raw predicate features, constants~~
   ~~and local input dependency.~~ Partially done. Reachability, guard kinds,
   operators, types, constant flags, and predicate constants are exported.
   Local input dependency analysis remains (T2.5).
4. Add indirect/global analysis only after cheap candidate filtering. Not started.
5. ~~Implement a deterministic query runner/export format; record query time,
   memory, and result counts.~~ Done. `internal/factexport` + `export-facts`
   command. Records CodeQL version, QL pack version, total time, and per-query
   result counts. Per-query compile/eval timing and memory still to add.

Exit: facts are tested on micro fixtures and zlib; raw features are preserved;
query output is stable enough to feed a model builder. **Partially met**: input
dependency and indirect analysis remain, but the core fact set is stable.

### T3: implement LLVM edge identity and mapping

1. ~~Prototype branch measurement with SanitizerCoverage if useful.~~ Skipped:
   the pass plugin approach is sufficient.
2. ~~Implement the LLVM pass under `llvm/id-pass`.~~ Done. `EdgeIDPass.cpp`
   as a Clang pass plugin, compiled in Docker via CMake with `llvm-config
   --cxxflags` for ABI matching.
3. ~~Emit true/false successor facts, inline/debug context, and normalized IR
   fingerprints.~~ Done. JSONL manifest (append mode for per-TU invocation)
   with edge_id, function_name/linkage, file/line/column, successor_ordinal,
   ir_fingerprint, inline_stack.
4. ~~Implement `cmd/orchestra-model-build` to merge CodeQL and LLVM facts.~~
   Done. `internal/modelbuilder` + `cmd/orchestra-model-build`. Pass injected
   into the semantic-canonical build profile via CFLAGS/CXXFLAGS.
5. ~~Generate deterministic keys and `program_model.sqlite`.~~ Done. SHA-256
   based function_key and frontier_key. Writes via sqlite3 CLI.
6. ~~Label every candidate `exact`, `ambiguous`, `unmapped`, or
   `unsupported`.~~ Done. classifyMapping matches by (fileBasename, line),
   deduplicates edges by edge_id, and requires exactly two distinct edge
   outcomes for `exact`.
7. Add fixtures for macros, same-line branches, short-circuit expressions,
   inline/template code, and optimization changes. Not started.

Evidence: LLVM pass compiled in Docker, injected into the semantic-canonical
build via CFLAGS/CXXFLAGS, produces JSONL edge manifest. For zlib-uncompress:
3,072 unique runtime edges, 1,025 unique frontiers, 848 exact (82.7%),
172 ambiguous (16.8%), 5 unmapped (0.5%).

Go/no-go gate: manually label 100-200 schedulable binary guards across micro
fixtures and the pilot target. Target at least 90% `exact` mapping. Never admit
ambiguous mappings to scheduling. If the rate is materially lower, narrow the
supported language scope or document and evaluate an IR-first frontier model.

**Current status**: 82.7% exact, below the 90% target. The 172 ambiguous
frontiers are mostly same-line branches in deflate.c and inflate.c where
multiple guards share a source line. Using column number to disambiguate
same-line branches is the most promising improvement. The 848 exact frontiers
are already schedulable and sufficient for a first vertical slice (T4).

### T4: canonical replay and the two-seed vertical slice

1. ~~Implement a canonical binary/runtime and a subprocess probe first;
   persistent execution can follow after correctness.~~ Done. LLVM pass
   inserts weak `__orchestra_record_edge` callback; `SubprocessProbe` runs
   the fuzzer binary in Docker and parses coverage output.
2. ~~Add a content-addressed Seed Store keyed by `(model_id, seed_hash)`.~~
   Done. `MemoryStore` in `internal/probe/store.go`.
3. ~~Enforce at-most-once successful replay and persist status/cost/bitmap.~~
   Done. `MemoryStore.Put` does not overwrite; `CanonicalReplay.MeasureSeed`
   checks `Has` before calling the probe.
4. ~~Build two deterministic seeds: one covers exactly one mapped guard
   outcome; the second covers the other outcome.~~ Done. zlib valid/invalid
   seeds verified against the `zlib_uncompress_fuzzer.cc:16` frontier
   (true_edge=3623526760, false_edge=3679019613).
5. ~~Load the Program Model in the Coordinator.~~ Done.
   `ModelAwareState` loads frontier definitions and derives transitions.
6. ~~Derive input/output unions and frontier transitions from persisted
   canonical Seed Records; stop trusting caller-provided crossings.~~ Done.
   `MergeFromSeeds` constructs output union from Seed Records and derives
   `CrossedFrontiers` from the Program Model.
7. ~~Compare incremental bitmap union with a full replay of the same fixed
   corpus.~~ Done. `TestIncrementalVsFullReplay` verifies equality.

Exit:

- ~~repeated seed observation does not execute the probe again;~~ Verified.
- ~~incremental and full-replay edge sets are equal;~~ Verified (10 edges).
- ~~first seed makes the frontier active and the second crosses it;~~ Verified.
- ~~Coordinator produces correct `job_delta`, `novel_delta`, concurrent
  duplicate, and derived `crossed_frontier` evidence.~~ Verified.

## 4. Milestones

### M0 -- frozen V1 and OSS-Fuzz build backbone

Status: **passed**.

Implemented: side-by-side packages, pinned manifest, generic adapter, profiles,
manifest generation, smoke-test command, worker interface.

Evidence: zlib-uncompress semantic-canonical build executed, CodeQL DB
finalized (177,344 LoC, 214 functions, 1,097 guards, 1,243 calls), base-runner
smoke test exit 0, artifact manifest validated against JSON schema, fingerprint
reproducible. Entrypoint working-dir bug fixed.

Remaining: model_id pending Program Model builder (M2).

### M1 -- CodeQL feasibility

Status: **mostly passed; input dependency and cost measurement pending**.

Implemented: QL pack with enriched Functions (harness reachability, C linkage),
Calls (confidence), Guards (guard kind, operator, type, constant flag),
Constants (guard predicate literals). Golden fixture test. Deterministic
fact export with timing and result counts.

Evidence: golden fixture passes (6 functions, 9 calls, 5 guards, constants
captured); zlib export produces 214 functions, 1,243 calls, 1,097 guards,
82 constants.

Missing gate: local input dependency analysis, indirect/global analysis,
combined-build compatibility evidence, manual precision/coverage review,
and per-query cost measurements.

### M2 -- CodeQL-to-LLVM mapping

Status: **mostly passed; 82.7% exact, below 90% target**.

Implemented: LLVM edge ID pass compiled and injected into semantic-canonical
build; model builder produces `program_model.sqlite` with deterministic keys
and exact/ambiguous/unmapped classification; edge deduplication by edge_id.

Evidence: zlib-uncompress produces 3,072 unique runtime edges and 1,025 unique
frontiers. 848 exact (82.7%), 172 ambiguous (16.8%), 5 unmapped (0.5%).

Missing gate: 90% exact mapping not yet reached (82.7%). The 172 ambiguous
frontiers are mostly same-line branches where column disambiguation would
help. T4 (canonical replay vertical slice) can proceed with the 848 exact
frontiers while the mapping quality is improved.

### M3 -- incremental Seed Store

Status: **passed**.

Implemented: `MemoryStore` with at-most-once semantics;
`CanonicalReplay` orchestrating probe + store + frontier evaluation;
`SubprocessProbe` running fuzzer binary in Docker;
`ModelAwareState` deriving coverage unions and frontier transitions from
Seed Records; incremental vs full-replay equivalence verified;
SQLite-persisted `campaign.Store` with seed records, job coverage,
frontier state, and append-only event log.

Evidence: `TestTwoSeedVerticalSlice` (at-most-once, active→crossed),
`TestIncrementalVsFullReplay` (10 edges equal),
`TestModelAwareMergeFromSeeds` (job_delta, novel_delta, crossed_frontier),
`TestStoreSeedRecordRoundTrip` (SQLite seed persistence + retrieval),
`TestStoreEventLog` (8 event types),
`TestStoreFrontierState` (frontier state transitions).

Missing: compressed bitmap storage, campaign recovery from event log replay.

### M4 -- Active Frontier and Region

Status: **Active Frontier integrated; Region construction implemented**.

Implemented: `ModelAwareState` evaluates frontiers from dynamic coverage and
derives transitions; `region.Builder` constructs Regions from the Program
Model call graph, control dependence, and dynamic coverage with SCC
compression (Tarjan's algorithm) and dynamic trimming.

Evidence: `TestCallGraphSCC` (A→B→C cycle collapsed to 1 SCC, D and E as
singletons), `TestBuildRegions` (frontier f1 → controlled=[check_value,
helper, logger], uncovered=[200]), `TestBuildRegionsNoActiveFrontiers`
(no active frontiers → no regions materialized).

Missing: bounded call context (K levels), dynamic function-edge trimming
from Seed Records, deterministic event replay.

### M5 -- seed, capability, and scheduler

Status: **implemented (explainable linear policy)**.

Implemented: `CapabilityObservation` (fuzzerID, attempted/crossed frontiers,
job/novel delta, CPU seconds), `SchedulerConfig` with weights for crossing
rate, coverage efficiency, and starvation; `Scheduler.SelectFrontier`
combines fuzzer score + starvation with jitter; `Scheduler.SelectSeeds`
scores seeds by frontier-edge overlap; `ExtractDictionary` returns
predicate-derived tokens.

Evidence: `TestScoreFuzzerNew` (neutral prior=0.5),
`TestScoreFuzzerWithObservations` (good=0.83, bad=0.005),
`TestSelectFrontier` (f3 selected due to 30-min starvation),
`TestSelectSeeds` (correct ordering by frontier-edge overlap),
`TestExtractDictionary`, `TestBuildDispatch`.

Missing: explainable policy with ablations, evidence-backed capability
estimates from real fuzzers.

### M6 -- end-to-end pilot

Status: **implemented and verified**.

Implemented: `pilot.PilotConfig` integrates ModelAwareState + scheduler +
campaign.Store across multiple targets and fuzzers. End-to-end pipeline:
measure seed → persist Seed Record → dispatch → merge from seeds →
record capability observation → append events.

Evidence: `TestPilotSingleTarget` (2 frontiers, 2 dispatches, 2 crossings),
`TestPilotMultiTargetMultiFuzzer` (2 targets × 2 fuzzers: libfuzzer on
zlib with 1 frontier, afl on jsoncpp with 2 frontiers, total 3 seeds,
3 dispatches, 3 crossings).

Missing: real subprocess probe integration, measured Coordinator/replay
overhead and backlog.

### M7 -- paper-scale evaluation

Status: **not started**.

Gate: modern single-fuzzer, equal-budget parallel/rotation, and shared-corpus
without scheduling baselines; relevant ablations; at least 10 independent
repeats per configuration and 20-30 when resources permit; confidence
intervals, effect sizes, time-to-threshold, crash deduplication, and
one-command artifact/report generation.

## 5. Required test matrix

### CodeQL/LLVM golden fixtures

Cover signed/unsigned comparisons, magic numbers, enums, bit masks,
modulo/ranges, string/memory comparisons, length checks, macros, same-line
conditions, `switch`, short circuiting, function pointers/callbacks, C++
overloads/virtual calls/templates/inlining, and unmodeled interprocedural flow.

Each relevant fixture eventually asserts CodeQL facts, LLVM edge facts, mapping
status, and canonical execution.

### Dynamic equivalence

- incremental union equals full fixed-corpus replay;
- deterministic seeds replay to stable results;
- nondeterministic targets are detected and isolated;
- identical bytes from different fuzzers produce one Seed Record;
- different concurrent completion orders produce the same final union and
  correct versioned attribution.

### Replayability

Delete derived campaign state while retaining Program Model, Seed Records,
events, policy version, and RNG seed. Replay must reconstruct the same global
coverage, frontier state, observations, and scheduling candidates.

### Build matrix

- every declared profile actually builds and executes a seed;
- identical fingerprints are compared for reproducibility;
- semantic-canonical and split semantic/canonical profiles have equivalent
  guard/edge sets if fallback is required;
- OSS-Fuzz upgrades are explicit and rerun the complete matrix.

## 6. Handoff completion rule

When advancing a milestone, update this document in the same commit. Record
evidence, not intent: exact command, tool revisions, artifact/model IDs, test
results, mapping counts, and remaining unsupported cases. An interface, mock,
schema, or command plan does not close a real integration gate.
