"""IAM schema: credentials, MFA, recovery, sessions and security telemetry."""
from sqlalchemy import Boolean, CheckConstraint, Column, ForeignKey, Index, Integer, LargeBinary, Table, Text, column, text
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.functions import FunctionElement


class JsonTextIsValid(FunctionElement):
    """Dialect-aware validity predicate for JSON retained in TEXT columns."""

    type = Boolean()
    inherit_cache = True


@compiles(JsonTextIsValid, "sqlite")
def _compile_sqlite_json_text_is_valid(element, compiler, **kwargs):
    argument = compiler.process(list(element.clauses)[0], **kwargs)
    return f"json_valid({argument})"


@compiles(JsonTextIsValid, "postgresql")
def _compile_postgresql_json_text_is_valid(element, compiler, **kwargs):
    argument = compiler.process(list(element.clauses)[0], **kwargs)
    # Invalid JSON text raises a cast error, rejecting the row at the constraint.
    return f"({argument})::jsonb IS NOT NULL"
from app.db_schema import metadata

iam_users = Table("iam_users", metadata,
    Column("id", Text, primary_key=True), Column("username", Text, nullable=False),
    Column("username_normalized", Text, nullable=False, unique=True), Column("role", Text, nullable=False),
    Column("status", Text, nullable=False, server_default="invited"), Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False), Column("activated_at", Text), Column("disabled_at", Text),
    Column("last_login_at", Text),
    CheckConstraint("role IN ('analyst', 'approver')", name="role"),
    CheckConstraint("status IN ('invited', 'active', 'disabled', 'locked')", name="status"),
    CheckConstraint("length(id) = 36", name="id_length"),
    CheckConstraint("length(username_normalized) BETWEEN 3 AND 128", name="username_length"))

iam_credentials = Table("iam_credentials", metadata,
    Column("user_id", Text, ForeignKey("iam_users.id", ondelete="RESTRICT"), primary_key=True),
    Column("password_hash", Text, nullable=False), Column("password_changed_at", Text, nullable=False),
    Column("must_change_password", Integer, nullable=False, server_default="1"),
    CheckConstraint("password_hash LIKE '$argon2id$%'", name="argon2id_hash"),
    CheckConstraint("must_change_password IN (0, 1)", name="must_change_password_boolean"))

iam_mfa_factors = Table("iam_mfa_factors", metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("iam_users.id", ondelete="RESTRICT"), nullable=False),
    Column("factor_type", Text, nullable=False), Column("secret_ciphertext", LargeBinary, nullable=False),
    Column("encryption_key_id", Text, nullable=False), Column("status", Text, nullable=False, server_default="pending"),
    Column("last_accepted_step", Integer), Column("created_at", Text, nullable=False),
    Column("confirmed_at", Text), Column("revoked_at", Text),
    CheckConstraint("factor_type = 'totp'", name="factor_type"),
    CheckConstraint("status IN ('pending', 'active', 'revoked')", name="status"),
    CheckConstraint("last_accepted_step IS NULL OR last_accepted_step >= 0", name="accepted_step"),
    CheckConstraint("length(id) = 36", name="id_length"),
    Index("idx_iam_mfa_factors_user_status", "user_id", "status"),
    Index("idx_iam_one_active_totp_per_user", "user_id", unique=True,
          sqlite_where=text("status = 'active' AND factor_type = 'totp'"),
          postgresql_where=text("status = 'active' AND factor_type = 'totp'")))

iam_recovery_codes = Table("iam_recovery_codes", metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("iam_users.id", ondelete="RESTRICT"), nullable=False),
    Column("code_hash", Text, nullable=False, unique=True), Column("created_at", Text, nullable=False),
    Column("used_at", Text), CheckConstraint("length(id) = 36", name="id_length"),
    Index("idx_iam_recovery_codes_user_unused", "user_id", "used_at"))

iam_access_tokens = Table("iam_access_tokens", metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("iam_users.id", ondelete="RESTRICT"), nullable=False),
    Column("token_hash", Text, nullable=False, unique=True), Column("token_prefix", Text, nullable=False),
    Column("scopes_json", Text, nullable=False, server_default="[]"),
    CheckConstraint(JsonTextIsValid(column("scopes_json")), name="scopes_json_valid"),
    Column("created_at", Text, nullable=False),
    Column("expires_at", Text, nullable=False), Column("last_used_at", Text), Column("revoked_at", Text),
    Column("revocation_reason", Text), CheckConstraint("length(id) = 36", name="id_length"),
    CheckConstraint("length(token_prefix) BETWEEN 4 AND 24", name="token_prefix_length"),
    Index("idx_iam_access_tokens_user_active", "user_id", "revoked_at", "expires_at"))

iam_sessions = Table("iam_sessions", metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("iam_users.id", ondelete="RESTRICT"), nullable=False),
    Column("session_hash", Text, nullable=False, unique=True), Column("created_at", Text, nullable=False),
    Column("last_seen_at", Text, nullable=False), Column("idle_expires_at", Text, nullable=False),
    Column("absolute_expires_at", Text, nullable=False), Column("revoked_at", Text), Column("mfa_verified_at", Text),
    CheckConstraint("length(id) = 36", name="id_length"),
    CheckConstraint("absolute_expires_at >= created_at", name="absolute_expiry"),
    CheckConstraint("idle_expires_at <= absolute_expires_at", name="idle_expiry"),
    Index("idx_iam_sessions_user_active", "user_id", "revoked_at", "idle_expires_at", "absolute_expires_at"))

iam_auth_challenges = Table("iam_auth_challenges", metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("iam_users.id", ondelete="RESTRICT"), nullable=False),
    Column("challenge_hash", Text, nullable=False, unique=True), Column("purpose", Text, nullable=False),
    Column("created_at", Text, nullable=False), Column("expires_at", Text, nullable=False),
    Column("consumed_at", Text), Column("failed_attempts", Integer, nullable=False, server_default="0"),
    CheckConstraint("purpose = 'login_mfa'", name="purpose"), CheckConstraint("failed_attempts >= 0", name="failed_attempts"),
    CheckConstraint("length(id) = 36", name="id_length"), CheckConstraint("expires_at > created_at", name="expiry"))

iam_activation_tokens = Table("iam_activation_tokens", metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("iam_users.id", ondelete="RESTRICT"), nullable=False),
    Column("token_hash", Text, nullable=False, unique=True), Column("created_at", Text, nullable=False),
    Column("expires_at", Text, nullable=False), Column("consumed_at", Text),
    CheckConstraint("length(id) = 36", name="id_length"), CheckConstraint("expires_at > created_at", name="expiry"))

iam_security_events = Table("iam_security_events", metadata,
    Column("id", Text, primary_key=True), Column("user_id", Text, ForeignKey("iam_users.id", ondelete="RESTRICT")),
    Column("event_type", Text, nullable=False), Column("occurred_at", Text, nullable=False),
    Column("source_ip", Text), Column("success", Integer, nullable=False),
    Column("metadata_json", Text, nullable=False, server_default="{}"),
    CheckConstraint(JsonTextIsValid(column("metadata_json")), name="metadata_json_valid"),
    CheckConstraint("success IN (0, 1)", name="success_boolean"), CheckConstraint("length(id) = 36", name="id_length"),
    Index("idx_iam_security_events_user_time", "user_id", "occurred_at"))

iam_auth_rate_limits = Table("iam_auth_rate_limits", metadata,
    Column("bucket_hash", Text, primary_key=True), Column("scope", Text, nullable=False),
    Column("window_started_at", Text, nullable=False), Column("failures", Integer, nullable=False),
    Column("blocked_until", Text), Column("updated_at", Text, nullable=False),
    CheckConstraint("length(scope) BETWEEN 1 AND 32", name="scope_length"),
    CheckConstraint("failures >= 1", name="failures"), CheckConstraint("length(bucket_hash) = 64", name="bucket_hash_length"),
    Index("idx_iam_auth_rate_limits_updated", "updated_at"))

iam_schema_migrations = Table("iam_schema_migrations", metadata,
    Column("version", Integer, primary_key=True), Column("name", Text, nullable=False, unique=True),
    Column("checksum", Text, nullable=False), Column("applied_at", Text, nullable=False))
