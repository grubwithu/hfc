// Weak stub for __orchestra_record_edge so that non-fuzzer binaries
// (zlib's own test programs) can link without the full runtime library.
// The strong version in edge_runtime.c overrides this when linked.
__attribute__((weak))
void __orchestra_record_edge(unsigned int edge_id) {
    (void)edge_id;
}
