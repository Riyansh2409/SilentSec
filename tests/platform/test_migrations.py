from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("authlib")

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from silentsec.platform import models


def test_upgrade_downgrade_and_metadata_match(platform):
    app, _, _, settings = platform
    config = Config()
    config.set_main_option("script_location", str(Path(models.__file__).parent / "migrations"))
    config.set_main_option(
        "sqlalchemy.url", settings.database_url.get_secret_value().replace("%", "%%")
    )
    command.check(config)
    command.downgrade(config, "base")
    assert set(inspect(app.state.engine).get_table_names()) == {"alembic_version"}
    command.upgrade(config, "head")
    command.check(config)


def test_billing_timezone_cannot_mint_overlapping_grants(platform):
    _, factory, account, _ = platform
    _, _, org_id = account("timezone@example.test")
    from sqlalchemy.exc import DatabaseError

    with pytest.raises(DatabaseError), factory.begin() as db:
        db.get(models.Organization, org_id).billing_timezone = "Asia/Kolkata"


def test_postgres_prevents_ledger_truncate(platform):
    app, factory, _, _ = platform
    if app.state.engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL-specific append-only guard")
    from sqlalchemy import text
    from sqlalchemy.exc import DatabaseError

    with pytest.raises(DatabaseError), factory.begin() as db:
        db.execute(text("TRUNCATE usage_ledger_entries"))
