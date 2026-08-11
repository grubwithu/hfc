# Orchestra V2 contracts

These contracts prevent build-time semantic objects, runtime coverage, and
online policy from leaking into one another. Go types and SQL/JSON schemas are
the executable representation; this document defines their intended meaning.

## 1. Authority and identity

| Fact | Authority |
|---|---|
| source function, call, guard, predicate features | CodeQL fact export |
| runtime edge execution | canonical LLVM instrumentation |
| CodeQL-to-runtime relation | Program Model builder |
| seed bytes and identity | content hash under one `model_id` |
| global novelty | Coordinator at merge time |
| Region/fuzzer decision | versioned policy consuming recorded facts |

CodeQL database entity IDs are extraction-local implementation details. They
must not appear as persistent `function_key`, `frontier_key`, or runtime edge
IDs. Persistent keys must be derived deterministically from normalized source,
linkage, predicate, and build identity. The model builder must document and
test its key algorithm before M2 is accepted.

Runtime edge IDs are deterministic only for the same Program Model inputs and
pass version. Cross-model numeric equality has no meaning. A `uint32` collision
must fail model construction.

## 2. Build artifact contract

`schema/artifact-manifest.schema.json` and `internal/artifact.Manifest` define
the current version-1 scaffold. A completed manifest records both declared
inputs and discovered outputs.

Required final provenance includes:

```text
OSS-Fuzz commit and project definition hash
source commit and source tree hash
fuzz target and primary source directory
profile, architecture, engine, sanitizer
compiler version and flags hash
Docker image digest
CodeQL and QL pack versions
LLVM pass and schema versions
binary hash and Program Model ID
```

The scaffold manifest does not yet carry every final field. Extending the Go
type, JSON schema, fingerprint logic, tests, and documentation together is an
M0/M1 requirement.

A build fingerprint excludes local checkout paths but includes every declared
input that can affect semantics or instrumentation. A cache hit is valid only
when the complete fingerprint matches. Engine, sanitizer, compiler flags, and
LLVM pass versions must never share incompatible object caches.

## 3. Program Model contract

`program_model.sqlite` is immutable after publication. Its identity covers all
build and analysis inputs. Online components open it read-only.

The minimum facts are represented by `schema/program_model.sql`:

- `builds`: provenance and schema identity;
- `functions`: stable function facts and harness reachability;
- `calls`: callsite, target kind, and confidence;
- `runtime_edges`: canonical edge IDs and IR fingerprints;
- `frontiers`: source predicates, input dependency, runtime outcomes, mapping;
- `frontier_tokens`: raw dictionary evidence;
- `control_dependence`: controlled blocks and distance.

### Mapping status

- `exact`: one source frontier maps to the intended distinct runtime outcomes;
- `ambiguous`: more than one plausible mapping remains;
- `unmapped`: no runtime relation was found;
- `unsupported`: the source/IR construct is outside the supported model.

Only `exact` is schedulable. Other statuses remain queryable and count toward
mapping-quality statistics.

### Predicate features

Predicate semantics are a feature vector, not a single category. Preserve raw
operators, types, signedness, constants, calls, boolean structure, masks,
ranges, and string/memory comparisons. Derived categories belong to a
versioned policy and must be reproducible from raw facts.

### Input dependency

The allowed classes and their meanings are defined in `DESIGN.md`. Unknown or
unmodeled flow must not be silently converted to input-independent.

## 4. Seed Record contract

`internal/contracts.SeedRecord` and the `seeds` table describe a canonical
measurement of one content-addressed input.

Identity is:

```text
(model_id, seed_hash)
```

The same bytes under a different Program Model require a separate record.
Within one model, a globally unseen seed is measured at most once. Retrying a
failed/incomplete measurement requires explicit status and retry semantics;
it must not create two successful authoritative measurements.

The canonical probe, not the producing fuzzer's bitmap, supplies
`edge_bitmap`. Function/frontier bitmaps are derived conveniences and must be
reconstructible from the authoritative edge bitmap and Program Model.

Persist at least:

- content hash, size, origin fuzzer/job, optional parent;
- first-seen time;
- canonical execution time and exit status;
- canonical edge bitmap;
- optional function/frontier projections;
- normalized crash signature.

## 5. Job contracts and coverage attribution

The current JSON message types are in `internal/contracts`.

### Dispatch

A dispatch records the Program Model and the global state version observed by
the scheduler, plus Region/frontier, fuzzer, seeds, tokens, and budget. The
Coordinator assigns `dispatch_state_version`; a worker must not invent it.

### Result

A worker reports produced candidate hashes and execution statistics. It may
report engine-local observations for diagnostics, but it is not authoritative
for global novelty.

The current scaffold accepts `input_union_bitmap`, `output_union_bitmap`, and
`crossed_frontier_ids` from the worker because it is a contract harness. The
production path must construct canonical unions from persisted Seed Records
and derive frontier transitions from the Program Model. It must not trust an
engine-native bitmap or unverified worker-reported crossing.

### Feedback formulas

For job `j`:

```text
job_delta(j) = output_union(j) - input_union(j)

novel_delta(j) =
  output_union(j) - global_coverage_at_merge(j)

dispatch_novel(j) =
  output_union(j) - global_coverage_at_dispatch(j)

concurrent_duplicate(j) =
  dispatch_novel(j) - novel_delta(j)
```

- `job_delta` measures local progress relative to the assigned inputs.
- `novel_delta` is the contribution still globally new when the job merges.
- `concurrent_duplicate` identifies work that looked new at dispatch but was
  covered by another job before this merge.

Keep all three. Do not use `job_delta` as a synonym for global novelty.

Merge order may change which job receives `novel_delta`, but the final global
coverage union must be order-independent. Event logs retain dispatch and merge
versions so alternative attribution can be analyzed offline.

## 6. Active Frontier contract

For a binary frontier with exact distinct `true_edge` and `false_edge`:

```text
evaluated = true_covered OR false_covered
partial   = true_covered XOR false_covered
```

States are:

- `unseen`: neither outcome is covered;
- `active`: exactly one outcome is covered and all eligibility rules pass;
- `crossed`: both outcomes are covered;
- `ineligible`: mapping, input-dependency, downstream, or structural rules do
  not permit scheduling.

An active evaluation records the covered and uncovered outcome IDs. Mapping
must be exact, input dependency must be supported, distinct outcomes must
exist, and uncovered downstream code must remain.

Campaign persistence may additionally use `retired` for a previously active
frontier disabled by evidence or policy. Retirement needs an event and reason;
it is not equivalent to an initially ineligible frontier.

## 7. Region contract

Region is a later milestone but its boundary is fixed:

```text
R = <Frontier F, bounded call context C, controlled subgraph G>
```

It is not a source interval or an enumerated root-to-leaf call path. Recursive
SCCs are collapsed, call context is bounded, and dynamic edge/function evidence
trims static over-approximation. Entry, frontier reach, local coverage, and
frontier conversion are distinct metrics; seed assignment never guarantees
entry.

## 8. Campaign persistence and events

`campaign.sqlite` stores jobs, Seed Records, coverage attribution, frontier
state, capability observations, and events. Production coordination must add
an append-only event stream containing at least:

```text
campaign_started, job_dispatched, seed_observed, seed_measured,
job_completed, coverage_merged, frontier_updated,
capability_updated, campaign_finished
```

Given the same immutable Program Model, successful Seed Records, event stream,
policy version, and RNG seed, replay must reconstruct the same derived global
coverage, frontier state, observations, and scheduling candidates.

## 9. Contract evolution

For an incompatible change:

1. increment the relevant schema version;
2. update Go types and SQL/JSON schemas together;
3. add upgrade/rejection behavior rather than accepting fields ambiguously;
4. add round-trip and unknown-field tests;
5. update this document and `ROADMAP.md`;
6. never mix Program Models or events with incompatible versions silently.
