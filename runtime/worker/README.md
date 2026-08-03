# Orchestra worker

Workers adapt fuzzer-specific commands and corpus layouts to the versioned
contracts in `internal/contracts`. They report only new candidate seeds and job
statistics. Workers do not query CodeQL, construct regions, or decide global
novelty.

The initial adapters should cover libFuzzer and OSS-Fuzz's AFL/AFL++ profile.
The migration may reuse pfuzzer's process-management and corpus-discovery code,
but the modified `libfuzzer.a` is not a V2 core API.
