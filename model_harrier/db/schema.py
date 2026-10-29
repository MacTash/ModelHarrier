"""SQLite database schema for ModelHarrier scans, telemetry, and watch targets."""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT DEFAULT 'completed',
    risk_score REAL,
    severity TEXT,
    file_count INTEGER DEFAULT 0,
    risky_file_count INTEGER DEFAULT 0,
    summary TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_model ON scans(model_id);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scans_severity ON scans(severity);

CREATE TABLE IF NOT EXISTS scan_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    format TEXT,
    verdict TEXT,
    risk_score REAL,
    details TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_files_scan ON scan_files(scan_id);

CREATE TABLE IF NOT EXISTS scan_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    cve TEXT,
    source TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_alerts_scan ON scan_alerts(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_alerts_cve ON scan_alerts(cve);

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    label TEXT NOT NULL,
    file_size INTEGER,
    aieye_score INTEGER,
    consensus_score INTEGER,
    is_false_positive BOOLEAN DEFAULT 0,
    is_false_negative BOOLEAN DEFAULT 0,
    has_reduce BOOLEAN DEFAULT 0,
    has_global BOOLEAN DEFAULT 0,
    dangerous_globals INTEGER DEFAULT 0,
    opcode_vector TEXT,
    model_type TEXT,
    confidence REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_telemetry_label ON telemetry(label);
CREATE INDEX IF NOT EXISTS idx_telemetry_hash ON telemetry(file_hash);
CREATE INDEX IF NOT EXISTS idx_telemetry_fp ON telemetry(is_false_positive);
CREATE INDEX IF NOT EXISTS idx_telemetry_fn ON telemetry(is_false_negative);

CREATE TABLE IF NOT EXISTS watch_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT NOT NULL UNIQUE,
    check_interval_hours INTEGER DEFAULT 24,
    last_checked TEXT,
    last_hash TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cve_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    package TEXT,
    severity TEXT,
    description TEXT,
    affected_versions TEXT,
    fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cve_package ON cve_cache(package);
CREATE TABLE IF NOT EXISTS probe_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT NOT NULL,
    category TEXT NOT NULL,
    probe_name TEXT NOT NULL,
    prompt TEXT,
    result TEXT DEFAULT 'untested',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_probes_model ON probe_results(model_id);
"""
