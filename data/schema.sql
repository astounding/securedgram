-- SecureDGram Database Schema
--
-- Usage:
--   sqlite3 /path/to/securedgram.db < schema.sql
--
-- The daemon creates these tables automatically on first start,
-- but this file can be used to pre-create the database or to
-- recreate it manually.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS outbound_messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT,
    dst_addr        TEXT NOT NULL,
    dst_port        INTEGER NOT NULL,
    payload         TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending',
    retry_count     INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    sent_at         TEXT,
    ack_received_at TEXT,
    last_error      TEXT,
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_outbound_message_id ON outbound_messages(message_id);
CREATE INDEX IF NOT EXISTS idx_outbound_state ON outbound_messages(state);

CREATE TABLE IF NOT EXISTS inbound_messages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id       TEXT NOT NULL,
    src_addr         TEXT NOT NULL,
    src_port         INTEGER NOT NULL,
    payload          TEXT NOT NULL,
    crypto_timestamp TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'received',
    ack_sent         INTEGER NOT NULL DEFAULT 0,
    read_count       INTEGER NOT NULL DEFAULT 0,
    received_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    ack_sent_at      TEXT,
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_inbound_message_id ON inbound_messages(message_id);
CREATE INDEX IF NOT EXISTS idx_inbound_state ON inbound_messages(state);
