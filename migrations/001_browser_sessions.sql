BEGIN;
CREATE TABLE user_sch.browser_session (
    uuid uuid PRIMARY KEY,
    user_uuid uuid NOT NULL REFERENCES user_sch."user"(uuid),
    tenant_uuid uuid NOT NULL,
    school_uuid uuid NOT NULL,
    expired_date timestamptz NOT NULL,
    revoke_date timestamptz,
    created_date timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE user_sch.browser_refresh_token (
    token_hash text PRIMARY KEY,
    session_uuid uuid NOT NULL REFERENCES user_sch.browser_session(uuid) ON DELETE CASCADE,
    used_date timestamptz
);
CREATE INDEX browser_refresh_session_idx ON user_sch.browser_refresh_token(session_uuid);
-- Legacy tokens are deliberately not accepted by the new session endpoints.
UPDATE user_sch.refresh_session SET revoke_date = now() WHERE revoke_date IS NULL;
COMMIT;
