# pfuzzer-hfc-patch

V2 versions of `FuzzerHFC.h` and `FuzzerHFC.cpp` for the pfuzzer submodule.

## Why this directory exists

The pfuzzer submodule (`pfuzzer/`) is a third-party fork of libFuzzer that
extends it with multi-engine fork coordination (`-fork`, `-fuzzers`).
V1 of Orchestra added its HTTP client as `FuzzerHFC.h/cpp` directly inside
the pfuzzer submodule (commit `caff817`).

V2 of Orchestra also uses pfuzzer for multi-engine fuzzing but talks to
a different HTTP API (`/v2/*` instead of `/peekResult`, `/corpus/upload`,
`/log`). To keep the pfuzzer submodule upstream-clean (so `git submodule
update` works without conflicts), V2's HTTP client lives here.

## How it is wired in

`cmd/orchestra-pfuzzer-build/main.go`:

1. Copies `pfuzzer-hfc-patch/FuzzerHFC.{h,cpp}` over `pfuzzer/FuzzerHFC.{h,cpp}`
   inside the submodule working tree.
2. Runs `cmake` + `make` to produce `libfuzzer.a`.
3. After successful build, restores the original submodule files from
   `git checkout FuzzerHFC.h FuzzerHFC.cpp` so the submodule working tree
   is clean again.

This means:

- The pfuzzer submodule commit hash never changes (`caff817`).
- V2's pfuzzer-side HTTP client is fully owned by the Orchestra repo.
- The compiled `libfuzzer.a` ends up in `build/v2/pfuzzer-build/libfuzzer.a`
  (already .gitignored).

## Compatibility note

`FuzzerHFC.h/cpp` keep the V1 data-structure names (`ConstraintGroup`,
`PeekResultResponce`) and function signatures (`PeekResult`, `ReportCorpus`,
`Log`, `Ready`) so the pfuzzer submodule's `FuzzerFork.cpp` compiles
unchanged. Only the HTTP wire format inside these functions is upgraded to
V2 endpoints.

The V1 typedef-name shadowing quirk (`ConstraintScore` typedef + struct
field of the same name) requires `-fpermissive` (set in
`cmd/orchestra-pfuzzer-build/main.go`'s cmake invocation).
