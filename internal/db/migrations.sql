CREATE TABLE IF NOT EXISTS events (
    id           BIGSERIAL PRIMARY KEY,
    chain_id     BIGINT NOT NULL,
    contract     TEXT   NOT NULL,
    event_name   TEXT   NOT NULL,
    block_number BIGINT NOT NULL,
    tx_hash      TEXT   NOT NULL,
    log_index    INT    NOT NULL,
    data         JSONB  NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (chain_id, tx_hash, log_index)
);

CREATE INDEX IF NOT EXISTS idx_events_chain_block ON events (chain_id, block_number);
CREATE INDEX IF NOT EXISTS idx_events_contract    ON events (contract);
CREATE INDEX IF NOT EXISTS idx_events_event_name  ON events (event_name);

CREATE TABLE IF NOT EXISTS checkpoints (
    chain_id   BIGINT PRIMARY KEY,
    last_block BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
