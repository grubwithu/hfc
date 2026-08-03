# Orchestra CodeQL model pack

This pack exports build-time facts consumed by `orchestra-model-build`. It is
deliberately limited to facts: region construction, runtime coverage, scoring,
and scheduling do not run inside CodeQL.

The first milestone contains functions, resolved direct calls, and `if` guards.
Later queries add predicate feature vectors, input dependency, tokens, indirect
calls with confidence, and harness reachability. Query output must preserve raw
features instead of reducing a predicate to one label.

Run the pack against a finalized database:

```bash
codeql database run-queries --threads=0 -- <database> codeql/orchestra-model
```

Pin both the CodeQL bundle and this pack version in every Program Model.
