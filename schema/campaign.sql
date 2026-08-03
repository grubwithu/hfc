PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA user_version = 1;

CREATE TABLE campaigns (
    campaign_id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    rng_seed INTEGER NOT NULL,
    state_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    dispatch_state_version INTEGER NOT NULL,
    merged_state_version INTEGER,
    region_id TEXT NOT NULL,
    fuzzer_id TEXT NOT NULL,
    status TEXT NOT NULL,
    dispatched_at TEXT NOT NULL,
    completed_at TEXT,
    time_budget_seconds INTEGER NOT NULL,
    max_executions INTEGER,
    executions INTEGER,
    execs_per_second REAL,
    wall_time_ns INTEGER,
    restart_overhead_ns INTEGER
);

CREATE INDEX jobs_by_campaign ON jobs(campaign_id, dispatched_at);

CREATE TABLE seeds (
    seed_hash TEXT NOT NULL,
    model_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    origin_fuzzer TEXT NOT NULL,
    origin_job TEXT NOT NULL REFERENCES jobs(job_id),
    parent_seed_hash TEXT,
    first_seen_at TEXT NOT NULL,
    canonical_execution_time_ns INTEGER NOT NULL,
    edge_bitmap BLOB NOT NULL,
    function_bitmap BLOB,
    frontier_bitmap BLOB,
    crash_signature TEXT,
    PRIMARY KEY (model_id, seed_hash)
);

CREATE TABLE job_seeds (
    job_id TEXT NOT NULL REFERENCES jobs(job_id),
    seed_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('input', 'output')),
    PRIMARY KEY (job_id, seed_hash, role)
);

CREATE TABLE job_coverage (
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
    input_union_bitmap BLOB NOT NULL,
    output_union_bitmap BLOB NOT NULL,
    job_delta_bitmap BLOB NOT NULL,
    novel_delta_bitmap BLOB NOT NULL,
    concurrent_duplicate_bitmap BLOB NOT NULL
);

CREATE TABLE frontier_state (
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    frontier_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('unseen', 'active', 'crossed', 'retired')),
    first_activated_version INTEGER,
    last_updated_version INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (campaign_id, frontier_key)
);

CREATE TABLE capability_observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    job_id TEXT NOT NULL REFERENCES jobs(job_id),
    fuzzer_id TEXT NOT NULL,
    predicate_feature_vector_json TEXT NOT NULL,
    attempted_frontiers INTEGER NOT NULL,
    crossed_frontiers INTEGER NOT NULL,
    job_delta_edges INTEGER NOT NULL,
    novel_delta_edges INTEGER NOT NULL,
    cpu_seconds REAL NOT NULL,
    executions INTEGER NOT NULL,
    replay_overhead_seconds REAL NOT NULL
);

CREATE TABLE events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    model_id TEXT NOT NULL,
    job_id TEXT,
    state_version INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX events_by_campaign ON events(campaign_id, sequence);
