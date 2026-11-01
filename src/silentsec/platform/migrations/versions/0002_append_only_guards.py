"""Protect append-only records against truncation and freeze approved pattern packs."""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

# Fixed DDL statements, written out (no string formatting) so the SQL is plain
# to review and static analysis does not see a formatted query.
TRUNCATE_GUARDS_POSTGRESQL = (
    "CREATE TRIGGER immutable_truncate_audit_events BEFORE TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION silentsec_immutable()",
    "CREATE TRIGGER immutable_truncate_credit_grants BEFORE TRUNCATE ON credit_grants FOR EACH STATEMENT EXECUTE FUNCTION silentsec_immutable()",
    "CREATE TRIGGER immutable_truncate_usage_ledger_entries BEFORE TRUNCATE ON usage_ledger_entries FOR EACH STATEMENT EXECUTE FUNCTION silentsec_immutable()",
    "CREATE TRIGGER immutable_truncate_entitlement_snapshots BEFORE TRUNCATE ON entitlement_snapshots FOR EACH STATEMENT EXECUTE FUNCTION silentsec_immutable()",
    "CREATE TRIGGER immutable_truncate_pattern_packs BEFORE TRUNCATE ON pattern_packs FOR EACH STATEMENT EXECUTE FUNCTION silentsec_immutable()",
)

DROP_TRUNCATE_GUARDS_POSTGRESQL = (
    "DROP TRIGGER immutable_truncate_audit_events ON audit_events",
    "DROP TRIGGER immutable_truncate_credit_grants ON credit_grants",
    "DROP TRIGGER immutable_truncate_usage_ledger_entries ON usage_ledger_entries",
    "DROP TRIGGER immutable_truncate_entitlement_snapshots ON entitlement_snapshots",
    "DROP TRIGGER immutable_truncate_pattern_packs ON pattern_packs",
)

PATTERN_PACK_GUARDS_SQLITE = (
    "CREATE TRIGGER immutable_pattern_packs_update BEFORE UPDATE ON pattern_packs BEGIN SELECT RAISE(ABORT, 'append-only record'); END",
    "CREATE TRIGGER immutable_pattern_packs_delete BEFORE DELETE ON pattern_packs BEGIN SELECT RAISE(ABORT, 'append-only record'); END",
)

DROP_PATTERN_PACK_GUARDS_SQLITE = (
    "DROP TRIGGER immutable_pattern_packs_update",
    "DROP TRIGGER immutable_pattern_packs_delete",
)


def upgrade():
    if op.get_bind().dialect.name == "postgresql":
        for statement in TRUNCATE_GUARDS_POSTGRESQL:
            op.execute(statement)
        op.execute(
            "CREATE TRIGGER immutable_pattern_packs BEFORE UPDATE OR DELETE ON pattern_packs FOR EACH ROW EXECUTE FUNCTION silentsec_immutable()"
        )
    else:
        for statement in PATTERN_PACK_GUARDS_SQLITE:
            op.execute(statement)


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for statement in DROP_TRUNCATE_GUARDS_POSTGRESQL:
            op.execute(statement)
        op.execute("DROP TRIGGER immutable_pattern_packs ON pattern_packs")
    else:
        for statement in DROP_PATTERN_PACK_GUARDS_SQLITE:
            op.execute(statement)
