CREATE TABLE outbox (
    id BIGSERIAL PRIMARY KEY,
    job_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'dead_lettered')),
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX idx_outbox_pending_retry
ON outbox (next_retry_at, created_at)
WHERE status = 'pending';

CREATE INDEX idx_outbox_dead_lettered
ON outbox (status)
WHERE status = 'dead_lettered';

CREATE OR REPLACE FUNCTION notify_outbox_insert() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('aegis_outbox', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_outbox_after_insert
AFTER INSERT ON outbox
FOR EACH ROW
WHEN (NEW.status = 'pending')
EXECUTE FUNCTION notify_outbox_insert();
