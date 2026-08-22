# Orchestra stable edge ID pass

## Overview

This LLVM pass instruments conditional branches and emits a JSON manifest
with deterministic edge IDs for every true/false successor. It is loaded as
a Clang pass plugin during the semantic-canonical build profile.

## Build

The pass is compiled inside the OSS-Fuzz builder container using the
installed LLVM headers and libraries. See `CMakeLists.txt`.

```bash
mkdir build && cd build
cmake .. -DLLVM_DIR=$(llvm-config --cmakedir)
make -j$(nproc)
```

The resulting `OrchestraEdgeIDPass.so` is loaded by Clang via:

```
-fpass-plugin=OrchestraEdgeIDPass.so
```

## Output format

The pass writes a JSON array to `$ORCHESTRA_EDGE_MANIFEST` (or stderr if
unset). Each entry contains:

```json
{
  "edge_id": 42,
  "function_name": "inflate",
  "function_linkage": "external",
  "file": "/src/zlib/inflate.c",
  "line": 250,
  "column": 3,
  "successor_ordinal": 0,
  "ir_fingerprint": "br_i1_cmp_eq_0_label_true_label_false",
  "inline_stack": []
}
```

## Requirements

1. Edge IDs are deterministic for the same source, build flags, and pass
   version. They are assigned by a stable hash of (function name, file, line,
   column, successor ordinal, IR fingerprint).
2. A source line is never assumed to identify one branch.
3. Macro expansion, short-circuit expressions, templates, and inline stacks
   are represented in the fingerprint.
4. The pass writes facts only; it does not attempt to resolve CodeQL entities.
5. The model builder labels every match as `exact`, `ambiguous`, `unmapped`,
   or `unsupported`. Only exact mappings may enter online scheduling.
