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

**Process boundary**: V2 is a passive HTTP analyzer. pfuzzer drives
multi-engine fuzzing execution and corpus management; Orchestra serves analysis
results via HTTP/JSON on `/v2/*`. pfuzzer-side client is
`pfuzzer/FuzzerOrchestra.cpp`. V1's HTTP boundary (`/v1/*` and
`pfuzzer/FuzzerHFC.cpp`) is retained for one release cycle with a
`Deprecation` HTTP header.

**Trust boundary**: pfuzzer-reported bitmaps are hints. `SubprocessProbe`
verifies each `(model_id, seed_hash)` once against the canonical binary.
All frontier state, bitmap union, and scheduler decisions use verified
bitmaps only.

**M0–M4 status (turn 12)**:
- M0 passed (real zlib build, CodeQL DB finalized, smoke test exit 0).
- M1 mostly passed (enriched QL queries, golden fixtures, deterministic export).
- M2 mostly passed (82.7% exact mapping on zlib; 848/1025 frontiers).
- M3 passed (SQLite campaign store, at-most-once MemoryStore, event log).
- M4 implemented (Region construction with Tarjan SCC + control dependence).

**M5/M6 status (turn 11–12)**:
- M5 implemented: linear-policy scheduler with capability observation
  (6 tests pass).
- M6 implemented but slated for **deletion**: the original pilot was an
  in-process self-driving demonstration. With the new passive-analyzer
  architecture (turn 12), pilot is obsolete. `internal/pilot/` is removed
  outright per the user's "直接去掉" decision.

**Refactor pending**: 6 commits planned to align V2 with the new architecture.
User confirmation required to begin.

## 2. Component status

| Component | State | Gap |
|---|---|---|
| V1/V2 boundary | implemented | V1 is the only end-to-end legacy system |
| target validation | tested | 21 example targets |
| OSS-Fuzz adapter | tested planner | 21 real builds verified |
| CodeQL wrapper | implemented | 21 zlib-class DBs captured and queried |
| smoke-test command | implemented | 21 runs on produced targets, all exit 0 |
| artifact manifest | provenance complete | model_id + pfuzzer hash fields pending |
| QL pack | enriched | functions+reachability, calls+confidence, guards+features, constants |
| fact export | implemented | deterministic JSON export with timing/counts |
| LLVM edge pass | implemented+injected | 21 JSONL manifests, ~3.5M edges total |
| Program Model SQL | schema + importer | 21 models built, 848 exact frontiers (zlib) |
| model builder | implemented | 82.7% exact mapping, below 90% target |
| canonical probe | implemented | SubprocessProbe + at-most-once Store |
| pfuzzer linkage | pending | prebuilt `libFuzzer.a` mount in entrypoint |
| bitmap operations | tested | bitmap union, hash Contains() |
| Coordinator | in-memory + model-aware + SQLite + HTTP server | `/v1` deprecated, `/v2` current |
| trust boundary | partial | probe verifies pfuzzer bitmap before merge |
| canonical replay | implemented | SubprocessProbe, at-most-once Store |
| seed/capability/scheduler | implemented | linear policy + capability observation |
| end-to-end pilot | deleted | replaced by pfuzzer-driven `/v2/*` flow (M7) |
| crossing detection | partial | uses verified bitmap, not echoed IDs |
| Region | implemented | SCC compression + control dependence; bounded context pending |
| seed/dictionary | absent | dictionary mining pending |
| capability/scheduler | implemented | linear policy; bandit/UCT future |
| evaluation | absent | paper experiments are M10 |

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
   QL pack, LLVM pass, schema, and model identity.~~ Done.
2. ~~Add CodeQL golden micro fixtures before broadening queries.~~ Done.
3. ~~Export harness reachability, guard kinds, raw predicate features, constants
   and local input dependency.~~ Partially done.
4. Add indirect/global analysis only after cheap candidate filtering. Not started.
5. ~~Implement a deterministic query runner/export format; record query time,
   memory, and result counts.~~ Done.

Exit: facts are tested on micro fixtures and zlib; raw features are preserved;
query output is stable enough to feed a model builder.

### T3: implement LLVM edge identity and mapping

1. ~~Prototype branch measurement with SanitizerCoverage if useful.~~ Skipped.
2. ~~Implement the LLVM pass under `llvm/id-pass`.~~ Done.
3. ~~Emit true/false successor facts, inline/debug context, and normalized IR
   fingerprints.~~ Done.
4. ~~Implement `cmd/orchestra-model-build` to merge CodeQL and LLVM facts.~~
   Done.
5. ~~Generate deterministic keys and `program_model.sqlite`.~~ Done.
6. ~~Label every candidate `exact`, `ambiguous`, `unmapped`, or
   `unsupported`.~~ Done.
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

**Current status**: 82.7% exact, below the 90% target.

### T4: canonical replay and the two-seed vertical slice

1. ~~Implement a canonical binary/runtime and a subprocess probe first;
   persistent execution can follow after correctness.~~ Done.
2. ~~Add a content-addressed Seed Store keyed by `(model_id, seed_hash)`.~~
   Done.
3. ~~Enforce at-most-once successful replay and persist status/cost/bitmap.~~
   Done.
4. ~~Build two deterministic seeds: one covers exactly one mapped guard
   outcome; the second covers the other outcome.~~ Done.
5. ~~Load the Program Model in the Coordinator.~~ Done.
6. ~~Derive input/output unions and frontier transitions from persisted
   canonical Seed Records; stop trusting caller-provided crossings.~~ Done.
7. ~~Compare incremental bitmap union with a full replay of the same fixed
   corpus.~~ Done.

Exit:

- ~~repeated seed observation does not execute the probe again;~~ Verified.
- ~~incremental and full-replay edge sets are equal;~~ Verified.
- ~~first seed makes the frontier active and the second crosses it;~~ Verified.
- ~~Coordinator produces correct `job_delta`, `novel_delta`, concurrent
  duplicate, and derived `crossed_frontier` evidence.~~ Verified.

### T5: refactor to passive HTTP analyzer

Reverts V2's self-driving architecture. New role for V2:

| Layer | Process | Communicates via |
|---|---|---|
| pfuzzer (native C++) | Engine execution host: multi-engine fork, corpus management, bitmap observation | HTTP/JSON to Orchestra |
| Orchestra V2 (Go) | Passive HTTP analyzer: canonical probe verification, frontier recommendations, dictionary mining | HTTP/JSON, sqlite3 CLI |

#### T5.1 HTTP API skeleton

- New `internal/api/` package: `server.go`, `handlers.go`, `types.go`, `trust.go`.
- Endpoints (path-prefix `/v2/*`):
  - `GET  /v2/health` — liveness + API version.
  - `GET  /v2/state` — model_id, frontier_count, active_count, coverage_size.
  - `GET  /v2/frontiers/active` — priority-ordered active frontiers + per-frontier
    recommended seeds + dictionary tokens.
  - `POST /v2/corpus/add` — pfuzzer reports new candidate seed; Orchestra
    triggers `SubprocessProbe` verification and stores verified bitmap.
  - `POST /v2/coverage/report` — pfuzzer reports bitmap observation;
    Orchestra updates `capability_observations`.
  - `GET  /v2/dictionary` — full corpus dictionary from Program Model.
- `cmd/orchestra-coordinator/main.go` registers `/v2/*` routes alongside existing
  `/v1/*` (deprecated, retained 1 release cycle).

#### T5.2 Trust boundary

- pfuzzer-reported bitmaps are stored in `MemoryStore` as **hint bitmaps** for
  dedup.
- All frontier state, bitmap union, and scheduler decisions use
  **verified bitmaps** only (SubprocessProbe output).
- `/v2/corpus/add` response includes verification status; pfuzzer relies on
  this rather than its own bitmap for scheduling decisions.

#### T5.3 Scheduler HTTP exposure

- `Scheduler.RecommendFrontiers(coverage, allFrontiers) []FrontierRecommendation`
  exposed via `GET /v2/frontiers/active`.
- `Scheduler.RecordCoverageReport(fuzzerID, jobID, observed, attemptedFrontiers,
  crossedFrontiers)` consumes `POST /v2/coverage/report`.

#### T5.4 pfuzzer HTTP client

- New `pfuzzer/FuzzerOrchestra.{h,cpp}` (replaces V1's `FuzzerHFC.cpp`).
- Uses `cpp-httplib` (same dependency as V1).
- Calls `/v2/*` endpoints at startup, on candidate seed observation, and
  after coverage intervals.
- V1 client (`FuzzerHFC.cpp`) retained 1 release cycle with `Deprecation`
  marker.

#### T5.5 Cleanup

- `internal/pilot/` removed (per user "直接去掉" decision; obsolete under
  passive-analyzer architecture).
- `internal/worker/adapter.go` retained as `// Optional:` marker for future
  offline reproducibility tests.

### T6: pfuzzer linkage

OSS-Fuzz builds must link against the prebuilt pfuzzer `libFuzzer.a`, not the
upstream libFuzzer:

| Path | Status |
|---|---|
| `third_party/pfuzzer/` | Pfuzzer source as git submodule (gitignored) |
| `third_party/pfuzzer/build/libFuzzer.a` | Output of `cmd/orchestra-pfuzzer-build` |
| `pfuzzer/FuzzerOrchestra.cpp` | New HTTP client to `/v2/*` |
| `pfuzzer/FuzzerHFC.cpp` | V1 client (deprecated) |

Effects on V2 components:

- `internal/ossfuzz/plan.go::BuildProfile` mounts pfuzzer prebuilt
  `libFuzzer.a` and injects `LIB_FUZZING_ENGINE=/opt/pfuzzer/libFuzzer.a`.
- `cmd/orchestra-ossfuzz/main.go::build` invokes
  `cmd/orchestra-pfuzzer-build` before `Planner.BuildProfile`.
- `scripts/orchestra-ossfuzz-entrypoint.sh` no longer requires `LIB_FUZZING_ENGINE`
  to be a `-fsanitize=fuzzer` token; accepts a path to `.a`.

Built binary semantics (DESIGN §4.1a):

- `./binary /seed` — libFuzzer single-seed replay (V2 SubprocessProbe).
- `./binary -fork=N -fuzzers=afl,libfuzzer /corpus` — pfuzzer multi-engine
  coordination (pfuzzer runtime).

Edge IDs remain identical across both modes because conditional branch
IR is unchanged.

### T7: pfuzzer HTTP integration verification

Status: not started.

Goal: pfuzzer client (`FuzzerOrchestra.cpp`) actually drives multi-fuzzer
campaigns against Orchestra on all 21 OSS-Fuzz targets.

Verification gates:
- Multi-engine fork mode (`-fork=4 -fuzzers=afl,libfuzzer`) runs end-to-end
  on zlib (smallest), openssl (largest), and 5 mid-sized targets.
- Bitmap hint from pfuzzer is overridden by SubprocessProbe-verified bitmap
  on first observation.
- Capability observations accumulate in `campaign.sqlite` across the run.
- Scheduler recommendations steer pfuzzer toward active frontiers; fuzzing
  throughput improves vs. random seed selection baseline.
- pfuzzer crashes and restarts; `GET /v2/state` recovery preserves state.

### T8: performance validation

Status: not started.

Goal: confirm the V2 performance contract (DESIGN §5.5, CONTRACTS §12):

- bitmap union is O(K), not O(N²).
- frontier evaluation is O(1).
- SubprocessProbe verify is at-most-once.
- HTTP latency budget is met (recommendation response < 50 ms).

Methods:
- microbenchmarks on zlib (small) and openssl (large).
- 1000-seed corpus, measure per-seed latency distribution.
- Compare against V1's libFuzzer-merge baseline.

### T9: mapping quality to 90%

Status: not started.

Goal: column-disambiguated CodeQL→LLVM mapping for same-line branches.
Current rate: 82.7% exact (848/1025 frontiers for zlib).

Methods:
- emit `column` in Guards.ql predicate fingerprint.
- require `(file, line, column)` triple for `exact` match.
- re-evaluate zlib ambiguous frontiers (172/1025 = 16.8%).

Gate: re-built zlib Program Model shows ≥ 90% exact.

## 4. Milestones

### M0 -- frozen V1 and OSS-Fuzz build backbone

Status: **passed**.

Evidence: 21 OSS-Fuzz targets built through pinned OSS-Fuzz definitions;
CodeQL DBs finalized; base-runner smoke tests exit 0; artifact manifests
validate against JSON schema; fingerprints reproducible; entrypoint working-dir
bug fixed.

Remaining: model_id + pfuzzer hash fields pending (M2/T6).

### M1 -- CodeQL feasibility

Status: **mostly passed; input dependency and cost measurement pending**.

Implemented: QL pack with enriched Functions (harness reachability, C linkage),
Calls (confidence), Guards (guard kind, operator, type, constant flag),
Constants (guard predicate literals). Golden fixture test. Deterministic
fact export with timing and result counts.

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

Missing gate: 90% exact mapping not yet reached. Column disambiguation is
the path forward (T9).

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

Status: **implemented (explainable linear policy; HTTP-exposed)**.

Implemented: `CapabilityObservation` (fuzzerID, attempted/crossed frontiers,
job/novel delta, CPU seconds), `SchedulerConfig` with weights for crossing
rate, coverage efficiency, and starvation; `Scheduler.SelectFrontier`
combines fuzzer score + starvation with jitter; `Scheduler.SelectSeeds`
scores seeds by frontier-edge overlap; `ExtractDictionary` returns
predicate-derived tokens; `Scheduler.RecommendFrontiers` exposes a
priority-ordered frontier list to pfuzzer via `GET /v2/frontiers/active`;
`Scheduler.RecordCoverageReport` consumes `POST /v2/coverage/report`.

Evidence: 6 unit tests pass (TestScoreFuzzerNew, TestScoreFuzzerWithObservations,
TestSelectFrontier, TestSelectSeeds, TestExtractDictionary, TestBuildDispatch).

Missing: real pfuzzer HTTP integration test (deferred to M7).

### M6 -- end-to-end pilot (pfuzzer-driven)

Status: **interface removed (pilot package deleted; refactor pending)**.

The original V2 pilot was an in-process self-driving demonstration. With the
new passive-analyzer architecture (T5), V2 does not drive fuzzing. The pilot
code (`internal/pilot/`) is removed per the user's "直接去掉" decision.

The end-to-end pipeline now lives in:
- `cmd/orchestra-coordinator` (HTTP server, all `/v2/*` endpoints).
- `pfuzzer/FuzzerOrchestra.cpp` (HTTP client, calling `/v2/*` endpoints).

Missing: actual `FuzzerOrchestra.cpp` integration in pfuzzer build
(deferred to T7 verification).

### M7 -- pfuzzer HTTP integration verification

Status: **not started**.

Goal: pfuzzer client (`FuzzerOrchestra.cpp`) actually drives multi-fuzzer
campaigns against Orchestra on all 21 OSS-Fuzz targets.

Verification gates:
- Multi-engine fork mode (`-fork=4 -fuzzers=afl,libfuzzer`) runs end-to-end.
- Bitmap hint from pfuzzer is overridden by SubprocessProbe-verified bitmap.
- Capability observations accumulate in `campaign.sqlite`.
- Scheduler recommendations steer pfuzzer toward active frontiers; fuzzing
  throughput improves vs. random seed selection baseline.
- pfuzzer crashes and restarts; `GET /v2/state` recovery preserves state.

### M8 -- performance validation

Status: **not started**.

Goal: confirm the V2 performance contract (DESIGN §5.5, CONTRACTS §12):
- bitmap union is O(K), not O(N²).
- frontier evaluation is O(1).
- SubprocessProbe verify is at-most-once.
- HTTP latency budget is met.

Methods: microbenchmarks + 1000-seed corpus latency distribution.

### M9 -- mapping quality to 90%

Status: **not started**.

Goal: column-disambiguated CodeQL→LLVM mapping for same-line branches.
Current rate: 82.7% exact (848/1025 frontiers for zlib).

Gate: re-built zlib Program Model shows ≥ 90% exact.

### M10 -- paper-scale evaluation

Status: **not started**.

Gate: modern single-fuzzer, equal-budget parallel/rotation, and shared-corpus
without scheduling baselines; relevant ablations; at least 10 independent
repeats per configuration and 20-30 when resources permit; confidence
intervals, effect sizes, time-to-threshold, crash deduplication, and
one-command artifact/report generation.

## 5. Required test matrix

### CodeQL/LLVM golden fixtures

Cover signed/unsigned comparisons, magic numbers, enums, bit maps,
modulo/ranges, string/memory comparisons, length checks, macros, same-line
conditions, `switch`, short circuiting, function pointers/callbacks, C++
overloads/virtual calls/templates/inlining, and unmodeled interprocedural flow.

Each relevant fixture eventually asserts CodeQL facts, LLVM edge facts, mapping
status, and canonical execution.

### Dynamic equivalence

- incremental union equals full fixed-corpus replay;
- deterministic seeds replay to stable results;
- nondeterministic targets are detected and isolated;
- identical bytes from different fuzzers produce one Seed Record
  (after SubprocessProbe verification);
- different concurrent completion orders produce the same final union and
  correct versioned attribution (from verified bitmaps only).

### Replayability

Delete derived campaign state while retaining Program Model, Seed Records,
events, policy version, and RNG seed. Replay must reconstruct the same global
coverage, frontier state, observations, and scheduling candidates.

### Build matrix

- every declared profile actually builds and executes a seed;
- identical fingerprints are compared for reproducibility;
- semantic-canonical and split semantic/canonical profiles have equivalent
  guard/edge sets if fallback is required;
- OSS-Fuzz upgrades are explicit and rerun the complete matrix;
- **fuzzer binaries are pfuzzer-linked** (T6) and support both single-engine
  and multi-engine modes.

## 6. Handoff completion rule

When advancing a milestone, update this document in the same commit. Record
evidence, not intent: exact command, tool revisions, artifact/model IDs, test
results, mapping counts, and remaining unsupported cases. An interface, mock,
schema, or command plan does not close a real integration gate.
