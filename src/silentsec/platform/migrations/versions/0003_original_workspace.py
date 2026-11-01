"""Connect original workflows through tenant-scoped jobs and separate quotas."""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workstation_repositories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("root_path", sa.String(4096), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.UniqueConstraint("organization_id", "root_path"),
    )
    op.create_table(
        "workstation_requests",
        sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("operation", sa.String(30), nullable=False),
        sa.Column("arguments", sa.JSON(), nullable=False),
        sa.Column("repository_id", sa.String(36), sa.ForeignKey("workstation_repositories.id")),
        sa.Column("input_ref", sa.String(36)),
    )
    op.create_table(
        "workstation_results",
        sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("contexts", sa.JSON(), nullable=False),
        sa.Column("sarif", sa.JSON()),
        sa.Column("report", sa.Text()),
        sa.Column("expires_at", sa.BigInteger(), nullable=False, index=True),
    )
    op.create_table(
        "operation_quota_reservations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=False, index=True
        ),
        sa.Column("operation", sa.String(40), nullable=False),
        sa.Column("units", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("period_start", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("organization_id", "job_id", "operation"),
    )


def downgrade():
    op.drop_table("operation_quota_reservations")
    op.drop_table("workstation_results")
    op.drop_table("workstation_requests")
    op.drop_table("workstation_repositories")
