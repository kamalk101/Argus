namespace Argus.Storage;

/// <summary>
/// Schema v1. One database file per monitoring session in production; the schema
/// still carries session_id on every table so a combined archive works too.
/// </summary>
internal static class Schema
{
    public const int Version = 1;

    public const string Sql = """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            target_path TEXT NOT NULL,
            target_sha256 TEXT,
            target_signer TEXT,
            mode TEXT NOT NULL DEFAULT 'launch',
            started_utc TEXT NOT NULL,
            ended_utc TEXT,
            status TEXT NOT NULL DEFAULT 'running',
            os_build TEXT,
            agent_version TEXT,
            elevated INTEGER NOT NULL DEFAULT 0,
            peak_score REAL NOT NULL DEFAULT 0,
            final_score REAL,
            verdict TEXT,
            loss_events INTEGER NOT NULL DEFAULT 0,
            loss_bytes INTEGER NOT NULL DEFAULT 0,
            config_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS processes (
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            pid INTEGER NOT NULL,
            parent_pid INTEGER,
            image_name TEXT,
            image_path TEXT,
            cmdline TEXT,
            start_utc TEXT NOT NULL,
            end_utc TEXT,
            exit_code INTEGER,
            signer TEXT,
            sha256 TEXT,
            integrity TEXT,
            scope_state TEXT NOT NULL,
            PRIMARY KEY (session_id, pid, start_utc)
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            seq INTEGER NOT NULL,
            ts_utc TEXT NOT NULL,
            kind TEXT NOT NULL,
            category TEXT NOT NULL,
            pid INTEGER NOT NULL,
            tid INTEGER,
            parent_pid INTEGER,
            image_name TEXT,
            image_path TEXT,
            target TEXT,
            path_key TEXT,
            remote_ip TEXT,
            remote_port INTEGER,
            protocol TEXT,
            host_name TEXT,
            bytes_out INTEGER,
            bytes_in INTEGER,
            detail TEXT,
            detail_text TEXT,
            observability TEXT NOT NULL,
            confidence REAL NOT NULL,
            source TEXT NOT NULL,
            scope_state TEXT NOT NULL,
            UNIQUE (session_id, seq)
        );

        CREATE INDEX IF NOT EXISTS ix_events_session_ts ON events(session_id, ts_utc);
        CREATE INDEX IF NOT EXISTS ix_events_session_pid_ts ON events(session_id, pid, ts_utc);
        CREATE INDEX IF NOT EXISTS ix_events_session_kind_ts ON events(session_id, kind, ts_utc);

        CREATE VIRTUAL TABLE IF NOT EXISTS events_fts
            USING fts5(target, detail_text, content='events', content_rowid='id');

        CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
            INSERT INTO events_fts(rowid, target, detail_text)
            VALUES (new.id, new.target, new.detail_text);
        END;

        CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
            INSERT INTO events_fts(events_fts, rowid, target, detail_text)
            VALUES ('delete', old.id, old.target, old.detail_text);
        END;

        CREATE TABLE IF NOT EXISTS event_rollups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            window_start_utc TEXT NOT NULL,
            window_end_utc TEXT NOT NULL,
            category TEXT NOT NULL,
            kind TEXT NOT NULL,
            pid INTEGER,
            target_prefix TEXT,
            count INTEGER NOT NULL,
            bytes_out INTEGER NOT NULL DEFAULT 0,
            bytes_in INTEGER NOT NULL DEFAULT 0,
            sample_seq INTEGER,
            UNIQUE (session_id, window_start_utc, category, kind, pid, target_prefix)
        );

        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            detection_key TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity INTEGER NOT NULL,
            base_confidence REAL NOT NULL,
            confidence REAL NOT NULL,
            categories INTEGER NOT NULL,
            scope_pid INTEGER NOT NULL,
            first_ts TEXT NOT NULL,
            last_ts TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL,
            reason TEXT NOT NULL,
            counterfactual TEXT NOT NULL,
            factors_json TEXT NOT NULL,
            mitre TEXT NOT NULL,
            weight REAL NOT NULL,
            UNIQUE (session_id, detection_key)
        );

        CREATE TABLE IF NOT EXISTS detection_evidence (
            detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
            seq INTEGER NOT NULL,
            role TEXT NOT NULL,
            PRIMARY KEY (detection_id, seq, role)
        );

        CREATE TABLE IF NOT EXISTS score_history (
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            ts_utc TEXT NOT NULL,
            score REAL NOT NULL,
            peak REAL NOT NULL,
            band TEXT NOT NULL,
            categories INTEGER NOT NULL,
            explanation TEXT NOT NULL,
            PRIMARY KEY (session_id, ts_utc)
        );

        CREATE TABLE IF NOT EXISTS gaps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            ts_utc TEXT NOT NULL,
            source TEXT NOT NULL,
            reason TEXT NOT NULL,
            lost_count INTEGER,
            detail TEXT
        );

        CREATE TABLE IF NOT EXISTS iocs (
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            label TEXT,
            source TEXT,
            PRIMARY KEY (kind, value)
        );
        """;
}
