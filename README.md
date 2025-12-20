# HFC (Heterogeneous Fusion Controller)
This is a module that runs with [pfuzzer](https://github.com/grubwithu/pfuzzer). It can tell pfuzzer which corpus to focus on.

## Usage

Pre-requisite:
- We currently use the LLVM built in [fuzz-introspector](https://github.com/ossf/fuzz-introspector) to generate static profiles of the target binary.
- CMake (support `--project-file`)
- `llvm-profdata` and `llvm-cov` are available in PATH.

Init submodule:

```
$ git submodule update --init --recursive
```

Run the demo:

```
$ bash scripts/run_demo.sh freetype2
```

This script will:
- Build HFC in `build` directory.
- Compile pfuzzer in `pfuzzer/build` directory, and we can get `libfuzzer.a`.
- Build the target(freetype2) binary.
  - Generate static profiles of the target binary(using llvm built in fuzz-introspector). (We can get `test/freetype2/build/ftfuzzer` as A)
  - Compile the target binary for coverage instrumentation. (We can get `test/freetype2/build-runtime/ftfuzzer_cov` as B)
  - Link `libfuzzer.a` to the target binary. (We can get `test/freetype2/build-runtime/ftfuzzer` as C)
  - (In fact, three binaries are generated. A is never used. B is used for coverage report in HFC. C is running as pfuzzer.)
- Run HFC and pfuzzer in parallel.
