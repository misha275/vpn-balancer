CREATE TABLE IF NOT EXISTS users (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    uuid       UUID NOT NULL DEFAULT gen_random_uuid(),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nodes (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    server     TEXT NOT NULL,
    port       INT  NOT NULL,
    outbound   JSONB NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS checks (
    ts         TIMESTAMPTZ NOT NULL,
    node_id    TEXT NOT NULL,
    tier       SMALLINT NOT NULL,
    ok         BOOLEAN NOT NULL,
    latency_ms INT NOT NULL DEFAULT 0,
    speed_kbps INT NOT NULL DEFAULT 0,
    target     TEXT NOT NULL DEFAULT '',
    error      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS checks_node_ts ON checks (node_id, ts DESC);
CREATE INDEX IF NOT EXISTS checks_ts ON checks (ts);

CREATE TABLE IF NOT EXISTS switches (
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    from_node TEXT NOT NULL DEFAULT '',
    to_node   TEXT NOT NULL,
    reason    TEXT NOT NULL DEFAULT ''
);

-- migrations (idempotent)
ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_token TEXT NOT NULL DEFAULT replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
CREATE UNIQUE INDEX IF NOT EXISTS users_sub_token ON users (sub_token);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS link TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS exit_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS exit_country TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS exit_checked TIMESTAMPTZ NOT NULL DEFAULT 'epoch';

CREATE TABLE IF NOT EXISTS settings (
    key     TEXT PRIMARY KEY,
    value   JSONB NOT NULL,
    updated TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- statistics: traffic per user by hour, last activity, history of the server load
CREATE TABLE IF NOT EXISTS traffic_hourly (
    hour      TIMESTAMPTZ NOT NULL,
    user_name TEXT NOT NULL,
    up        BIGINT NOT NULL DEFAULT 0,
    down      BIGINT NOT NULL DEFAULT 0,
    conns     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, user_name)
);
CREATE TABLE IF NOT EXISTS user_seen (
    user_name TEXT PRIMARY KEY,
    last_seen TIMESTAMPTZ NOT NULL,
    last_ip   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS metrics (
    ts    TIMESTAMPTZ PRIMARY KEY,
    cpu   REAL NOT NULL DEFAULT 0,
    mem   REAL NOT NULL DEFAULT 0,
    disk  REAL NOT NULL DEFAULT 0,
    load1 REAL NOT NULL DEFAULT 0,
    up    REAL NOT NULL DEFAULT 0,
    down  REAL NOT NULL DEFAULT 0,
    conns INT NOT NULL DEFAULT 0,
    users INT NOT NULL DEFAULT 0
);

-- quality data kept with the node: last speed measurements (with dates), last check, results per service
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS speed_hist JSONB NOT NULL DEFAULT '[]';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS speed_try_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS speed_err TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS check_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS svc JSONB NOT NULL DEFAULT '{}';

-- WireGuard: the balancer's own key pair and the peers (routers, devices) that connect to it
CREATE TABLE IF NOT EXISTS wg_server (
    id          INT PRIMARY KEY,
    private_key TEXT NOT NULL,
    public_key  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wg_peers (
    name        TEXT PRIMARY KEY,
    private_key TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    address     TEXT NOT NULL,
    subnets     JSONB NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created     TIMESTAMPTZ NOT NULL DEFAULT now()
);
