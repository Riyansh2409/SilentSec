"""Protect append-only records against truncation and freeze approved pattern packs."""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    if op.get_bind().dialect.name == "postgresql":
        for table in (
            "audit_events",
            "credit_grants",
            "usage_ledger_entries",
            "entitlement_snapshots",
            "pattern_packs",
        ):
            op.execute(
                f"CREATE TRIGGER immutable_truncate_{table} BEFORE TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION silentsec_immutable()"
            )
        op.execute(
            "CREATE TRIGGER immutable_pattern_packs BEFORE UPDATE OR DELETE ON pattern_packs FOR EACH ROW EXECUTE FUNCTION silentsec_immutable()"
        )
    else:
        for operation in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER immutable_pattern_packs_{operation.lower()} BEFORE {operation} ON pattern_packs BEGIN SELECT RAISE(ABORT, 'append-only record'); END"
            )


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for table in (
            "audit_events",
            "credit_grants",
            "usage_ledger_entries",
            "entitlement_snapshots",
            "pattern_packs",
        ):
            op.execute(f"DROP TRIGGER immutable_truncate_{table} ON {table}")
        op.execute("DROP TRIGGER immutable_pattern_packs ON pattern_packs")
    else:
        for operation in ("update", "delete"):
            op.execute(f"DROP TRIGGER immutable_pattern_packs_{operation}")
