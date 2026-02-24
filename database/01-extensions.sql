-- Extensions required for UUID and encryption
CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- For gen_random_uuid() and encryption
CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; -- Backup for UUIDs

-- Audit comment
COMMENT ON EXTENSION pgcrypto IS 'UUID generator and cryptographic functions';