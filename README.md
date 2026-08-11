# Orchestra: Coordinating Multiple Fuzzers to Solve Code Constraint Bottlenecks
This is a module that runs with [pfuzzer](https://github.com/grubwithu/pfuzzer). It can tell pfuzzer which corpus to focus on.

> HFC is an alias of Orchestra.

## V2 refactoring scaffold

The repository now contains a side-by-side V2 scaffold under `cmd/`,
`internal/`, `codeql/`, `schema/`, and `experiments/`. It uses OSS-Fuzz as the
target build backend, CodeQL for build-time semantic facts, and versioned
runtime/coordinator contracts. The existing implementation remains unchanged
as the V1 experiment-reproduction baseline.

Start with [docs/v2/README.md](docs/v2/README.md). The complete handoff is split
into the [design](docs/v2/DESIGN.md), [contracts](docs/v2/CONTRACTS.md), and
[roadmap/current status](docs/v2/ROADMAP.md). Coding agents must also follow
[AGENTS.md](AGENTS.md).

## Usage

> Docker is recommended to run Orchestra.

Pre-requisite:
- Clang-18, LLVM-18, CMake, Build-essential, and so on...
- `llvm-profdata`, `llvm-opt`, and `llvm-cov` are needed in PATH.
- There is a environment variable `FUZZ_INTRO` to specify the path of `FuzzIntrospector.so`.

Init submodule:
```
$ git submodule update --init --recursive
```

Run the demo:
```
$ bash scripts/run_demo.sh freetype2 --default -seed_strategy=6 -fuzzer_strategy=6 -orchestra_dict=1
```

This script will:
- Build Orchestra in `build` directory.
- Compile pfuzzer in `pfuzzer/build` directory, and we can get `libfuzzer.a`.
- Build the target(freetype2) binary.
  - Generate static profiles of the target binary(using opt and fuzz-introspector). (We can get `test/freetype2/build__HFC_qzmp__/ftfuzzer` as A)
  - Compile the target binary for coverage instrumentation. (We can get `test/freetype2/build-runtime/ftfuzzer_cov` as B)
  - Link `libfuzzer.a` to the target binary. (We can get `test/freetype2/build-runtime/ftfuzzer` as C)
  - (In fact, three binaries are generated. A is never used. B is used for coverage report in HFC. C is running as pfuzzer.)
- Run HFC and pfuzzer in parallel.

## Run in Docker

We provide Dockerfiles to build the test environment.
```
$ bash script/build_images.sh
$ docker run -it --privileged hfc-freetype2 bash
## Inside the container
$ bash script/run_demo.sh freetype2 --default -seed_strategy=6 -fuzzer_strategy=6 -orchestra_dict=1
```

This may take a long while to build 21 targets. You can build them manually by the following command:
```
$ docker build -t hfc-base:latest .
$ cd test/
$ docker build -t hfc-test:latest -f base.Dockerfile .
$ docker build -t hfc-freetype2:latest -f dockerfile/freetype2.Dockerfile
```
