-- Per-blob encryption algorithm: enables live migration to a new AEAD
-- (reads follow the stored value, writes use the configured one, `keys
-- rekey` converts the backlog). Adding a new algorithm requires extending
-- this CHECK in a follow-up migration - deliberate: an unknown value here
-- is data corruption, not configuration.
ALTER TABLE cids ADD COLUMN pii_alg TEXT NOT NULL DEFAULT 'aes256gcm'
    CHECK (pii_alg IN ('aes256gcm', 'xchacha20poly1305'));
