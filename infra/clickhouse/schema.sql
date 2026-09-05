-- Blue Team OS telemetry store. Partition by month, order by tenant/time/type.
CREATE DATABASE IF NOT EXISTS blueteam;

CREATE TABLE IF NOT EXISTS blueteam.events
(
    event_id String,
    tenant_id String,
    timestamp DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC'),
    source LowCardinality(String),
    source_type LowCardinality(String),
    event_type LowCardinality(String),
    category LowCardinality(String),
    host_id String DEFAULT '',
    user_id String DEFAULT '',
    src_ip String DEFAULT '',
    dst_ip String DEFAULT '',
    src_port UInt16 DEFAULT 0,
    dst_port UInt16 DEFAULT 0,
    protocol LowCardinality(String) DEFAULT '',
    process_name String DEFAULT '',
    parent_process_name String DEFAULT '',
    command_line String DEFAULT '',
    domain String DEFAULT '',
    url String DEFAULT '',
    file_path String DEFAULT '',
    file_hash String DEFAULT '',
    action LowCardinality(String) DEFAULT '',
    outcome LowCardinality(String) DEFAULT '',
    severity LowCardinality(String) DEFAULT 'informational',
    confidence Float32 DEFAULT 1,
    schema_version LowCardinality(String) DEFAULT '1.0.0',
    attributes String DEFAULT '{}',
    raw_reference String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, event_type, event_id);

CREATE TABLE IF NOT EXISTS blueteam.network_sessions
(
    session_id String,
    tenant_id String,
    src String,
    dst String,
    protocol LowCardinality(String),
    start DateTime64(3, 'UTC'),
    end DateTime64(3, 'UTC'),
    duration_ms UInt64,
    bytes_in UInt64,
    bytes_out UInt64,
    packets UInt64,
    dns String DEFAULT '',
    tls String DEFAULT '',
    http String DEFAULT '',
    zeek_refs Array(String),
    suricata_refs Array(String),
    risk Float32 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(start)
ORDER BY (tenant_id, start, session_id);
