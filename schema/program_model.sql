PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;

CREATE TABLE schema_meta (
    schema_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    generator_version TEXT NOT NULL
);

CREATE TABLE builds (
    model_id TEXT PRIMARY KEY,
    source_commit TEXT NOT NULL,
    source_tree_hash TEXT NOT NULL,
    oss_fuzz_commit TEXT NOT NULL,
    oss_fuzz_project TEXT NOT NULL,
    build_profile TEXT NOT NULL,
    project_definition_hash TEXT NOT NULL,
    build_command_hash TEXT NOT NULL,
    compiler_version TEXT NOT NULL,
    codeql_version TEXT NOT NULL,
    ql_pack_version TEXT NOT NULL,
    llvm_pass_version TEXT NOT NULL,
    schema_version INTEGER NOT NULL
);

CREATE TABLE functions (
    function_key TEXT PRIMARY KEY,
    qualified_name TEXT NOT NULL,
    file TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    start_column INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_column INTEGER NOT NULL,
    linkage TEXT NOT NULL,
    cyclomatic_complexity INTEGER,
    reachable_from_harness INTEGER NOT NULL CHECK (reachable_from_harness IN (0, 1))
);

CREATE INDEX functions_by_file ON functions(file, start_line);

CREATE TABLE calls (
    callsite_key TEXT PRIMARY KEY,
    caller_key TEXT NOT NULL REFERENCES functions(function_key),
    callee_key TEXT REFERENCES functions(function_key),
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column INTEGER NOT NULL,
    dispatch_kind TEXT NOT NULL CHECK (dispatch_kind IN ('direct', 'function_pointer', 'virtual', 'unknown')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

CREATE INDEX calls_by_caller ON calls(caller_key);
CREATE INDEX calls_by_callee ON calls(callee_key);

CREATE TABLE runtime_edges (
    edge_id INTEGER PRIMARY KEY,
    function_key TEXT REFERENCES functions(function_key),
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column INTEGER NOT NULL,
    successor_ordinal INTEGER NOT NULL,
    ir_fingerprint TEXT NOT NULL UNIQUE
);

CREATE TABLE frontiers (
    frontier_key TEXT PRIMARY KEY,
    function_key TEXT NOT NULL REFERENCES functions(function_key),
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column INTEGER NOT NULL,
    predicate_fingerprint TEXT NOT NULL,
    predicate_type_vector_json TEXT NOT NULL,
    input_dependency_class TEXT NOT NULL CHECK (
        input_dependency_class IN (
            'none', 'local_direct', 'interprocedural_modeled',
            'interprocedural_unmodeled', 'unknown'
        )
    ),
    true_edge_id INTEGER REFERENCES runtime_edges(edge_id),
    false_edge_id INTEGER REFERENCES runtime_edges(edge_id),
    mapping_status TEXT NOT NULL CHECK (
        mapping_status IN ('exact', 'ambiguous', 'unmapped', 'unsupported')
    ),
    mapping_confidence REAL NOT NULL CHECK (mapping_confidence >= 0.0 AND mapping_confidence <= 1.0),
    CHECK (mapping_status != 'exact' OR (true_edge_id IS NOT NULL AND false_edge_id IS NOT NULL))
);

CREATE INDEX frontiers_by_function ON frontiers(function_key);
CREATE INDEX frontiers_by_mapping ON frontiers(mapping_status);

CREATE TABLE frontier_tokens (
    frontier_key TEXT NOT NULL REFERENCES frontiers(frontier_key),
    token_kind TEXT NOT NULL,
    token_value BLOB NOT NULL,
    source_kind TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    PRIMARY KEY (frontier_key, token_kind, token_value, source_kind)
);

CREATE TABLE control_dependence (
    frontier_key TEXT NOT NULL REFERENCES frontiers(frontier_key),
    controlled_block_key TEXT NOT NULL,
    distance INTEGER NOT NULL CHECK (distance >= 0),
    PRIMARY KEY (frontier_key, controlled_block_key)
);
