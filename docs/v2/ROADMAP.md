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

No real OSS-Fuzz/CodeQL artifact bundle is present in the repository or handoff
workspace. Consequently M0 is still in progress. Command generation tests are
not evidence that zlib compiled or that CodeQL captured translation units.

## 2. Component status

| Component | State | Gap |
|---|---|---|
| V1/V2 boundary | implemented | V1 is the only end-to-end system |
| target validation | tested | one example target |
| OSS-Fuzz adapter | tested planner | real zlib build unverified |
| CodeQL wrapper | implemented | no captured DB inspected |
| smoke-test command | implemented | not run on a produced target |
| artifact manifest | implemented | provenance fields incomplete |
| QL pack | initial prototype | functions, direct calls, `if` only |
| LLVM edge pass | specification | no pass, runtime, or manifest |
| Program Model SQL | schema prototype | no importer or published DB |
| model validation | small type/test | no SQLite loader or mapper |
| canonical probe | interfaces | no executable, bitmap, or store |
| worker | interfaces | no engine adapter or watcher |
| bitmap operations | tested | not compressed or persistent |
| Coordinator | in-memory tests | no DB, events, recovery, or model |
| coverage attribution | tested | caller supplies unions |
| Active Frontier | pure evaluator | not integrated or persistent |
| crossing detection | absent | worker IDs are echoed |
| Region | absent | design only |
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

1. Add missing manifest/model provenance: source tree, compiler/flags, CodeQL,
   QL pack, LLVM pass, schema, and model identity.
2. Add CodeQL golden micro fixtures before broadening queries.
3. Export harness reachability, guard kinds, raw predicate features, constants,
   and local input dependency.
4. Add indirect/global analysis only after cheap candidate filtering.
5. Implement a deterministic query runner/export format; record query time,
   memory, and result counts.

Exit: facts are tested on micro fixtures and zlib; raw features are preserved;
query output is stable enough to feed a model builder.

### T3: implement LLVM edge identity and mapping

1. Prototype branch measurement with SanitizerCoverage if useful.
2. Implement the LLVM pass under `llvm/id-pass`.
3. Emit true/false successor facts, inline/debug context, and normalized IR
   fingerprints.
4. Implement `cmd/orchestra-model-build` to merge CodeQL and LLVM facts.
5. Generate deterministic keys and `program_model.sqlite`.
6. Label every candidate `exact`, `ambiguous`, `unmapped`, or `unsupported`.
7. Add fixtures for macros, same-line branches, short-circuit expressions,
   inline/template code, and optimization changes.

Go/no-go gate: manually label 100-200 schedulable binary guards across micro
fixtures and the pilot target. Target at least 90% `exact` mapping. Never admit
ambiguous mappings to scheduling. If the rate is materially lower, narrow the
supported language scope or document and evaluate an IR-first frontier model.

### T4: canonical replay and the two-seed vertical slice

1. Implement a canonical binary/runtime and a subprocess probe first;
   persistent execution can follow after correctness.
2. Add a content-addressed Seed Store keyed by `(model_id, seed_hash)`.
3. Enforce at-most-once successful replay and persist status/cost/bitmap.
4. Build two deterministic seeds: one covers exactly one mapped guard outcome;
   the second covers the other outcome.
5. Load the Program Model in the Coordinator.
6. Derive input/output unions and frontier transitions from persisted canonical
   Seed Records; stop trusting caller-provided crossings.
7. Compare incremental bitmap union with a full replay of the same fixed corpus.

Exit:

- repeated seed observation does not execute the probe again;
- incremental and full-replay edge sets are equal;
- first seed makes the frontier active and the second crosses it;
- Coordinator produces correct `job_delta`, `novel_delta`, concurrent duplicate,
  and derived `crossed_frontier` evidence.

## 4. Milestones

### M0 -- frozen V1 and OSS-Fuzz build backbone

Status: **in progress**.

Implemented: side-by-side packages, pinned manifest, generic adapter, profiles,
manifest generation, smoke-test command, worker interface.

Missing gate: a verified real-target build, CodeQL capture, artifact validation,
and repeatability record.

### M1 -- CodeQL feasibility

Status: **started**.

Implemented: QL pack plus prototype Functions, direct Calls, and `if` Guards.

Missing gate: golden fixtures, harness reachability, predicate features,
constants, input dependency, combined-build compatibility evidence, manual
precision/coverage review, and cost measurements.

### M2 -- CodeQL-to-LLVM mapping

Status: **not started; specification only**.

Gate: stable pass/model builder plus the 100-200 guard review and approximately
90% exact mapping target described in T3.

### M3 -- incremental Seed Store

Status: **interfaces/schema only**.

Gate: content deduplication, canonical replay, compressed/persistent bitmaps,
coverage equivalence, and per-job cost approximately linear in new seeds.

### M4 -- Active Frontier and Region

Status: **Active Frontier pure evaluator implemented; Region not started**.

Gate: Program Model integration, SCC-compressed bounded Regions, dynamic
trimming, and deterministic event replay without root-to-leaf enumeration.

### M5 -- seed, capability, and scheduler

Status: **not started and intentionally blocked**.

Gate: diverse Region-affine seed selection, predicate-aware dictionaries,
evidence-backed capability estimates, and an explainable policy with ablations.

### M6 -- end-to-end pilot

Status: **not started**.

Gate: two mechanism-distinct modern fuzzers on 2-3 targets, stable campaigns,
and measured Coordinator/replay overhead and backlog.

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
