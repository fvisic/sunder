-- Seed the v1 key versions. The keys table holds metadata only; material
-- lives in the keystore and is created by EnsureKeys at startup/rotation.
INSERT INTO keys (key_id, kind, status) VALUES
    ('hmac-email/v1', 'hmac-email', 'ACTIVE'),
    ('hmac-phone/v1', 'hmac-phone', 'ACTIVE'),
    ('hmac-name/v1',  'hmac-name',  'ACTIVE'),
    ('pii-kek/v1',    'pii-kek',    'ACTIVE'),
    ('oti-sign/v1',   'oti-sign',   'ACTIVE');
