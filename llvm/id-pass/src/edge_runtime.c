// Orchestra edge coverage runtime library.
//
// This library provides the __orchestra_record_edge callback that the
// OrchestraEdgeIDPass inserts at the entry of each conditional branch
// successor. It records covered edge IDs in a set and writes them to
// a file at program exit.
//
// The output file path is controlled by the ORCHESTRA_COVERAGE_OUT
// environment variable. If unset, no output is written.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EDGES 65536

static uint32_t covered_edges[MAX_EDGES];
static size_t covered_count = 0;
static int initialized = 0;

static void dump_coverage(void) {
    const char *out_path = getenv("ORCHESTRA_COVERAGE_OUT");
    if (!out_path || !out_path[0]) {
        return;
    }
    FILE *f = fopen(out_path, "w");
    if (!f) {
        fprintf(stderr, "OrchestraEdgeRT: cannot open %s\n", out_path);
        return;
    }
    for (size_t i = 0; i < covered_count; i++) {
        fprintf(f, "%u\n", covered_edges[i]);
    }
    fclose(f);
}

static void init(void) {
    if (initialized) return;
    initialized = 1;
    atexit(dump_coverage);
}

__attribute__((visibility("default"), weak))
void __orchestra_record_edge(uint32_t edge_id) {
    init();
    if (covered_count < MAX_EDGES) {
        // Check for duplicates (linear scan is fine for small edge counts).
        for (size_t i = 0; i < covered_count; i++) {
            if (covered_edges[i] == edge_id) {
                return;
            }
        }
        covered_edges[covered_count++] = edge_id;
    }
}
