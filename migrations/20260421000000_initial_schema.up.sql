-- Enable uuid extension for uuid_generate_v7()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Seed identity tables
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    email_verified_at TIMESTAMPTZ,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending_verification', 'active', 'disabled', 'deleted')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT email_unique_case_insensitive UNIQUE (LOWER(email))
);

CREATE INDEX idx_users_status_active ON users (status) WHERE status = 'active';
CREATE INDEX idx_users_deleted_at ON users (deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_users_metadata_gin ON users USING GIN (metadata);

CREATE TABLE guests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    converted_to UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT email_unique_if_present UNIQUE (email)
);

CREATE INDEX idx_guests_expires_at ON guests (expires_at);
CREATE INDEX idx_guests_converted ON guests (converted_to) WHERE converted_to IS NOT NULL;

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash BYTEA NOT NULL UNIQUE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    guest_id UUID REFERENCES guests(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mfa_verified BOOLEAN NOT NULL DEFAULT false,
    user_agent TEXT,
    ip_address TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,

    CONSTRAINT session_identity_check CHECK (
        (user_id IS NOT NULL AND guest_id IS NULL) OR
        (user_id IS NULL AND guest_id IS NOT NULL)
    )
);

CREATE INDEX idx_sessions_token_hash ON sessions (token_hash);
CREATE INDEX idx_sessions_user_active ON sessions (user_id, expires_at)
    WHERE expires_at > NOW() AND user_id IS NOT NULL;
CREATE INDEX idx_sessions_guest_active ON sessions (guest_id, expires_at)
    WHERE expires_at > NOW() AND guest_id IS NOT NULL;
CREATE INDEX idx_sessions_cleanup ON sessions (expires_at) WHERE expires_at < NOW();

-- Credential tables
CREATE TABLE password_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    algorithm_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    UNIQUE (user_id)
);

CREATE INDEX idx_password_credentials_user ON password_credentials (user_id);

CREATE TABLE passkey_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    attestation_object BYTEA,
    authenticator_data BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports TEXT[],
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    UNIQUE (user_id, credential_id)
);

CREATE INDEX idx_passkey_credentials_user ON passkey_credentials (user_id);
CREATE INDEX idx_passkey_credentials_lookup ON passkey_credentials (credential_id);

CREATE TABLE totp_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'SHA1',
    digits INT NOT NULL DEFAULT 6,
    period INT NOT NULL DEFAULT 30,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (user_id)
);

CREATE INDEX idx_totp_credentials_user ON totp_credentials (user_id);

CREATE TABLE recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (user_id, code_hash)
);

CREATE INDEX idx_recovery_codes_unused ON recovery_codes (user_id) WHERE used_at IS NULL;

-- Access control tables
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    permissions JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_roles_name ON roles (LOWER(name));

CREATE TABLE user_role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    UNIQUE (user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON user_role_assignments (user_id);
CREATE INDEX idx_user_roles_expiry ON user_role_assignments (expires_at) WHERE expires_at IS NOT NULL;

-- Audit table
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'guest', 'service', 'system')),
    actor_id UUID,
    target_type TEXT,
    target_id UUID,
    ip_address TEXT,
    user_agent TEXT,
    request_id UUID,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_actor ON audit_logs (actor_type, actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at);
CREATE INDEX idx_audit_logs_metadata_gin ON audit_logs USING GIN (metadata);

-- Token tables (email verification + password reset)
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (token_hash)
);

CREATE INDEX idx_email_verification_tokens_user ON email_verification_tokens (user_id);
CREATE INDEX idx_email_verification_tokens_expiry ON email_verification_tokens (expires_at) WHERE expires_at < NOW();

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (token_hash)
);

CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens (user_id);
CREATE INDEX idx_password_reset_tokens_expiry ON password_reset_tokens (expires_at) WHERE expires_at < NOW();
