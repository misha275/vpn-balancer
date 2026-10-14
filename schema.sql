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

-- subscription period of a user (NULL = no limit); after this moment the key stops working
ALTER TABLE users ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- public site: accounts of people who registered themselves (each one owns a VPN user), sessions, plans, payments
CREATE TABLE IF NOT EXISTS accounts (
    id         BIGSERIAL PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    pass_hash  TEXT NOT NULL,
    user_id    BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    blocked    BOOLEAN NOT NULL DEFAULT false,
    note       TEXT NOT NULL DEFAULT '',
    created    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash TEXT PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires    TIMESTAMPTZ NOT NULL,
    ip         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS web_sessions_account ON web_sessions (account_id);
CREATE TABLE IF NOT EXISTS plans (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    days        INT NOT NULL CHECK (days > 0),
    price_cents INT NOT NULL DEFAULT 0 CHECK (price_cents >= 0),
    currency    TEXT NOT NULL DEFAULT 'RUB',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    sort        INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS payments (
    id           BIGSERIAL PRIMARY KEY,
    account_id   BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    plan_name    TEXT NOT NULL,
    days         INT NOT NULL,
    amount_cents INT NOT NULL,
    currency     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',   -- pending | paid | canceled
    provider     TEXT NOT NULL DEFAULT '',
    created      TIMESTAMPTZ NOT NULL DEFAULT now(),
    paid_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS payments_account ON payments (account_id, created DESC);
CREATE INDEX IF NOT EXISTS payments_status ON payments (status, created DESC);

-- certificates of the site (Let's Encrypt) survive the recreation of the container
CREATE TABLE IF NOT EXISTS acme_cache (
    key     TEXT PRIMARY KEY,
    data    BYTEA NOT NULL,
    updated TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- own nodes (not part of the balancer pool) and bundles of them; users get them only as subscriptions
CREATE TABLE IF NOT EXISTS custom_nodes (
    id      BIGSERIAL PRIMARY KEY,
    name    TEXT NOT NULL,
    link    TEXT NOT NULL,
    note    TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bundles (
    id      BIGSERIAL PRIMARY KEY,
    slug    TEXT NOT NULL UNIQUE,
    name    TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    sort    INT NOT NULL DEFAULT 0,
    created TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bundle_nodes (
    bundle_id BIGINT NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
    node_id   BIGINT NOT NULL REFERENCES custom_nodes(id) ON DELETE CASCADE,
    sort      INT NOT NULL DEFAULT 0,
    PRIMARY KEY (bundle_id, node_id)
);
-- which subscriptions a user may take: users.subs (NULL = by plan or default), plans.subs (NULL = default)
ALTER TABLE users ADD COLUMN IF NOT EXISTS subs TEXT[];
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_id BIGINT REFERENCES plans(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_fetched TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_fetches BIGINT NOT NULL DEFAULT 0;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS subs TEXT[];
ALTER TABLE payments ADD COLUMN IF NOT EXISTS plan_id BIGINT;

-- external servers (version 3.2): sources are subscriptions imported into the same list; every server works in one of two modes:
--   direct: users get the link of that server; via: users connect to this server (the gateway) and it forwards their traffic there
CREATE TABLE IF NOT EXISTS ext_sources (
    id        BIGSERIAL PRIMARY KEY,
    name      TEXT NOT NULL,
    url       TEXT NOT NULL,
    mode      TEXT NOT NULL DEFAULT 'direct' CHECK (mode IN ('direct','via')),
    enabled   BOOLEAN NOT NULL DEFAULT true,
    refreshed TIMESTAMPTZ,
    error     TEXT NOT NULL DEFAULT '',
    created   TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE custom_nodes ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'direct';
ALTER TABLE custom_nodes ADD COLUMN IF NOT EXISTS source_id BIGINT REFERENCES ext_sources(id) ON DELETE CASCADE;
ALTER TABLE custom_nodes ADD COLUMN IF NOT EXISTS uniq TEXT NOT NULL DEFAULT '';
ALTER TABLE custom_nodes ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE UNIQUE INDEX IF NOT EXISTS custom_nodes_source_uniq ON custom_nodes(source_id, uniq) WHERE source_id IS NOT NULL;
-- a category may contain the main server (its three balancers), single servers and whole sources
ALTER TABLE bundles ADD COLUMN IF NOT EXISTS with_main BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS bundle_sources (
    bundle_id BIGINT NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
    source_id BIGINT NOT NULL REFERENCES ext_sources(id) ON DELETE CASCADE,
    PRIMARY KEY (bundle_id, source_id)
);

-- блокировка пользователя: неуплата, бан, другое (с причиной); заблокированный не получает ключ и подписку
ALTER TABLE users ADD COLUMN IF NOT EXISTS block_kind TEXT CHECK (block_kind IN ('unpaid','ban','other'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS block_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_at TIMESTAMPTZ;

-- форум для сообщений об ошибках и вопросов (виден вошедшим пользователям сайта; модерация в панели)
CREATE TABLE IF NOT EXISTS forum_topics (
    id         BIGSERIAL PRIMARY KEY,
    account_id BIGINT REFERENCES accounts(id) ON DELETE SET NULL,
    kind       TEXT NOT NULL DEFAULT 'bug' CHECK (kind IN ('bug','question','idea','other')),
    title      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
    pinned     BOOLEAN NOT NULL DEFAULT false,
    hidden     BOOLEAN NOT NULL DEFAULT false,
    created    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_post  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS forum_topics_order ON forum_topics (pinned DESC, last_post DESC);
CREATE TABLE IF NOT EXISTS forum_posts (
    id         BIGSERIAL PRIMARY KEY,
    topic_id   BIGINT NOT NULL REFERENCES forum_topics(id) ON DELETE CASCADE,
    account_id BIGINT REFERENCES accounts(id) ON DELETE SET NULL,
    staff      BOOLEAN NOT NULL DEFAULT false,
    body       TEXT NOT NULL,
    hidden     BOOLEAN NOT NULL DEFAULT false,
    created    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS forum_posts_topic ON forum_posts (topic_id, id);
