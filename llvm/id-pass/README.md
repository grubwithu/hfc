# Orchestra stable edge ID pass

This directory reserves the build boundary for the LLVM pass. The first
implementation should instrument conditional branches and emit a manifest with
the following fields for each true/false successor:

```text
edge_id
function linkage/name
debug file, line, and column
inline stack
successor ordinal
normalized IR fingerprint
```

Requirements:

1. IDs are deterministic for the same source, build flags, and pass version.
2. A source line is never assumed to identify one branch.
3. Macro expansion, short-circuit expressions, templates, and inline stacks are
   represented in the fingerprint.
4. The pass writes facts only; it does not attempt to resolve CodeQL entities.
5. The model builder labels every match as `exact`, `ambiguous`, `unmapped`, or
   `unsupported`. Only exact mappings may enter online scheduling.

The shared object will be injected through the semantic-canonical build
profile, avoiding a replacement compiler wrapper whenever Clang's pass-plugin
flags are sufficient.
