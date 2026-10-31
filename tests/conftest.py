"""Shared test setup."""

import pytest


@pytest.fixture(autouse=True)
def _no_developer_env_file(monkeypatch, tmp_path):
    """Keep a developer's real .env (API keys) out of every test run."""
    monkeypatch.setenv("SILENTSEC_ENV_FILE", str(tmp_path / "no-such.env"))
