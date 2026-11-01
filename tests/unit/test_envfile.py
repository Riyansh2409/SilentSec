import os

import pytest

from silentsec import envfile
from silentsec.envfile import load_env_file, parse_env_text


def test_parse_handles_comments_quotes_export_and_bad_lines():
    text = (
        "# comment\n"
        "\n"
        "GROQ_API_KEY=gsk_plain\n"
        'GEMINI_API_KEY="AIza quoted # not a comment"\n'
        "export OLLAMA_MODEL='qwen2.5-coder:7b'\n"
        "OLLAMA_TIMEOUT=120 # seconds\n"
        "not a line\n"
        "1BAD=x\n"
        "EMPTY=\n"
    )
    assert parse_env_text(text) == {
        "GROQ_API_KEY": "gsk_plain",
        "GEMINI_API_KEY": "AIza quoted # not a comment",
        "OLLAMA_MODEL": "qwen2.5-coder:7b",
        "OLLAMA_TIMEOUT": "120",
        "EMPTY": "",
    }


@pytest.fixture
def clean(monkeypatch):
    for name in ("SSEC_T_A", "SSEC_T_B", "SSEC_T_EMPTY"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_load_never_overrides_and_skips_empty(tmp_path, clean):
    file = tmp_path / ".env"
    file.write_text("SSEC_T_A=from-file\nSSEC_T_B=new\nSSEC_T_EMPTY=\n", encoding="utf-8")
    clean.setenv("SSEC_T_A", "already-set")
    loaded = load_env_file(file)
    assert loaded == ["SSEC_T_B"]
    assert os.environ["SSEC_T_A"] == "already-set"
    assert os.environ["SSEC_T_B"] == "new"
    assert "SSEC_T_EMPTY" not in os.environ


def test_load_returns_names_not_values(tmp_path, clean):
    file = tmp_path / ".env"
    file.write_text("SSEC_T_A=supersecretvalue\n", encoding="utf-8")
    assert load_env_file(file) == ["SSEC_T_A"]


def test_missing_or_oversized_file_is_ignored(tmp_path, clean):
    assert load_env_file(tmp_path / "missing.env") == []
    big = tmp_path / "big.env"
    big.write_text("SSEC_T_A=" + "x" * 70_000, encoding="utf-8")
    assert load_env_file(big) == []
    assert "SSEC_T_A" not in os.environ


def test_explicit_variable_wins_and_cwd_is_never_read(tmp_path, clean, monkeypatch):
    scanned = tmp_path / "scanned-repo"
    scanned.mkdir()
    (scanned / ".env").write_text("SSEC_T_A=untrusted\n", encoding="utf-8")
    monkeypatch.chdir(scanned)
    trusted = tmp_path / "trusted.env"
    trusted.write_text("SSEC_T_B=trusted\n", encoding="utf-8")
    monkeypatch.setenv(envfile.ENV_FILE_VARIABLE, str(trusted))
    assert load_env_file() == ["SSEC_T_B"]
    assert "SSEC_T_A" not in os.environ


def test_checkout_env_file_points_at_repo_root():
    path = envfile.checkout_env_file()
    assert path is not None
    assert (path.parent / "pyproject.toml").is_file()
