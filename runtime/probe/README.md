# Canonical probe runtime

The probe will execute each globally unseen seed once against the stable-edge
binary and return sorted edge IDs plus execution status. It is independent of
the producing fuzzer, which makes coverage comparable across engines.

The Go-side interface is `internal/probe.Probe`. A persistent in-process driver
is preferred; forkserver or subprocess execution is an explicit fallback for
targets that cannot safely reset state.
