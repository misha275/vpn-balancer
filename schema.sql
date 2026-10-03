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
