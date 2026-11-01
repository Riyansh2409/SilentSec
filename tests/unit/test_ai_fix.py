"""AI fix proposals: the model's edits are validated and turned into a patch."""

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from silentsec.remediation.ai_fix import (
    AIFixStatus,
    FixProposalError,
    LineEdit,
    ai_fix_and_verify,
    build_patch,
    propose_fix,
    read_source_window,
)
from silentsec.remediation.fix_providers import (
    GeminiFixProvider,
    GroqFixProvider,
    build_default_fix_providers,
)
from silentsec.remediation.patch import validate_patch
from silentsec.remediation.sandbox import apply_patch, create_isolated_copy
from silentsec.remediation.verify import FixVerdict
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings

SOURCE = '''import sqlite3

API_TOKEN = "ghp_1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4rS5tU"


def find_user(conn, name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return conn.execute(query).fetchall()
'''

GOOD_EDITS = [
    {
        "start_line": 7,
        "end_line": 8,
        "replacement": (
            '    query = "SELECT * FROM users WHERE name = ?"\n'
            "    return conn.execute(query, (name,)).fetchall()"
        ),
    }
]


def make_finding(**overrides) -> Finding:
    values = {
        "fingerprint": "fp-sql",
        "tool": "semgrep",
        "rule_id": "sql-injection",
        "file_path": "db.py",
        "start_line": 8,
        "end_line": 8,
        "category": FindingCategory.SECURITY,
        "severity": Severity.HIGH,
        "message": "SQL built with string formatting",
        "cwe_id": "CWE-89",
    }
    values.update(overrides)
    return Finding(**values)


class FakeProvider:
    def __init__(self, *answers, name: str = "fake:model"):
        self.answers = list(answers)
        self.name = name
        self.model = "model"
        self.prompts: list[str] = []

    def complete(self, *, system: str, user: str) -> str:
        self.prompts.append(user)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, str) else json.dumps(answer)


def answer(edits, fingerprint: str = "fp-sql") -> dict:
    return {"fingerprint": fingerprint, "explanation": "Use a parameterized query.", "edits": edits}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "db.py").write_text(SOURCE, encoding="utf-8")
    return root


# --- source window ----------------------------------------------------------


def test_window_is_numbered_and_redacts_secrets(repo: Path):
    window = read_source_window(repo, make_finding())

    assert "8:     return conn.execute(query).fetchall()" in window.numbered_text
    assert "ghp_" not in window.numbered_text
    assert window.redacted_lines == [3]
    assert window.first_line == 1 and window.last_line == 8


def test_window_rejects_paths_outside_repository(repo: Path):
    with pytest.raises((FixProposalError, OSError)):
        read_source_window(repo, make_finding(file_path="../outside.py"))


def test_prompt_never_contains_the_secret(repo: Path):
    provider = FakeProvider(answer(GOOD_EDITS))

    propose_fix(repo, make_finding(), [provider])

    assert "ghp_" not in provider.prompts[0]
    assert "untrusted" in provider.prompts[0]


# --- patch building ---------------------------------------------------------


def test_good_edit_becomes_a_valid_patch_that_applies(repo: Path):
    window = read_source_window(repo, make_finding())
    diff = build_patch(window, [LineEdit(**GOOD_EDITS[0])])

    assert validate_patch(diff).ok
    assert "-    return conn.execute(query).fetchall()" in diff
    if shutil.which("git"):
        with create_isolated_copy(repo) as copy:
            assert apply_patch(copy, diff).ok
            assert "(name,)" in (copy.root / "db.py").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        ({"start_line": 3, "end_line": 3, "replacement": 'API_TOKEN = ""'}, "redacted"),
        ({"start_line": 7, "end_line": 7, "replacement": "x = '[REDACTED]'"}, "redacted"),
        ({"start_line": 40, "end_line": 41, "replacement": "x = 1"}, "not shown"),
        ({"start_line": 8, "end_line": 7, "replacement": "x = 1"}, "ends before"),
        (
            {"start_line": 8, "end_line": 8, "replacement": "    return conn.execute(query).fetchall()"},
            "do not change",
        ),
    ],
)
def test_unsafe_or_useless_edits_are_rejected(repo: Path, edit: dict, message: str):
    window = read_source_window(repo, make_finding())

    with pytest.raises(FixProposalError, match=message):
        build_patch(window, [LineEdit(**edit)])


def test_overlapping_edits_are_rejected(repo: Path):
    window = read_source_window(repo, make_finding())
    edits = [
        LineEdit(start_line=7, end_line=8, replacement="a"),
        LineEdit(start_line=8, end_line=8, replacement="b"),
    ]

    with pytest.raises(FixProposalError, match="overlap"):
        build_patch(window, edits)


def test_file_without_trailing_newline_produces_applicable_patch(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "db.py").write_text(SOURCE.rstrip("\n"), encoding="utf-8")
    window = read_source_window(root, make_finding())

    diff = build_patch(window, [LineEdit(**GOOD_EDITS[0])])

    assert "\\ No newline at end of file" in diff
    if shutil.which("git"):
        with create_isolated_copy(root) as copy:
            assert apply_patch(copy, diff).ok, diff


def test_crlf_file_keeps_crlf_line_endings(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "db.py").write_bytes(SOURCE.replace("\n", "\r\n").encode())
    window = read_source_window(root, make_finding())

    diff = build_patch(window, [LineEdit(**GOOD_EDITS[0])])

    assert '+    query = "SELECT * FROM users WHERE name = ?"\r\n' in diff


# --- provider fallback ------------------------------------------------------


def test_invalid_answer_falls_back_to_next_provider(repo: Path):
    broken = FakeProvider("not json", name="first")
    good = FakeProvider(answer(GOOD_EDITS), name="second")

    proposal, errors = propose_fix(repo, make_finding(), [broken, good])

    assert proposal is not None and proposal.provider == "second"
    assert errors and "first" in errors[0]
    assert proposal.requires_human_review


def test_wrong_fingerprint_and_unsafe_edits_fall_back(repo: Path):
    wrong = FakeProvider(answer(GOOD_EDITS, fingerprint="other"), name="wrong")
    unsafe = FakeProvider(
        answer([{"start_line": 3, "end_line": 3, "replacement": "x = 1"}]), name="unsafe"
    )

    proposal, errors = propose_fix(repo, make_finding(), [wrong, unsafe])

    assert proposal is None
    assert len(errors) == 2


def test_model_may_decline(repo: Path):
    proposal, errors = propose_fix(repo, make_finding(), [FakeProvider(answer([]))])

    assert proposal is None
    assert "declined" in errors[0]


def test_timeout_falls_back(repo: Path):
    proposal, _ = propose_fix(
        repo,
        make_finding(),
        [FakeProvider(TimeoutError("slow")), FakeProvider(answer(GOOD_EDITS))],
    )

    assert proposal is not None


# --- end to end with a fake scanner ------------------------------------------


def scan_of(findings):
    return RepositoryScanResult(
        repo_path="r",
        status=ScannerStatus.SUCCESS,
        scanners=[ScannerRunResult(scanner="semgrep", status=ScannerStatus.SUCCESS, duration_seconds=0)],
        findings=findings,
        duration_seconds=0,
        security_debt=score_findings(findings),
        security_debt_complete=True,
    )


class Scanner:
    def __init__(self, *results):
        self.results = list(results)

    def __call__(self, root, **kwargs):
        return self.results.pop(0)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_ai_fix_is_verified_and_original_untouched(repo: Path):
    finding = make_finding()
    scanner = Scanner(scan_of([finding]), scan_of([finding]), scan_of([]))

    report = ai_fix_and_verify(repo, providers=[FakeProvider(answer(GOOD_EDITS))], scan=scanner)

    assert report.status == AIFixStatus.PROPOSED
    assert report.verification.verdict == FixVerdict.VERIFIED_FIX
    assert report.finding_location == "db.py:8"
    assert (repo / "db.py").read_text(encoding="utf-8") == SOURCE


def test_secret_findings_are_refused_without_calling_a_model(repo: Path):
    secret = make_finding(fingerprint="fp-secret", category=FindingCategory.SECRET, start_line=3)
    provider = FakeProvider()

    report = ai_fix_and_verify(
        repo, fingerprint="fp-secret", providers=[provider], scan=Scanner(scan_of([secret]))
    )

    assert report.status == AIFixStatus.REFUSED
    assert provider.prompts == []


def test_unknown_fingerprint_and_missing_providers(repo: Path):
    report = ai_fix_and_verify(
        repo, fingerprint="nope", providers=[FakeProvider()], scan=Scanner(scan_of([make_finding()]))
    )
    assert report.status == AIFixStatus.NO_PROPOSAL

    report = ai_fix_and_verify(repo, providers=[], scan=Scanner(scan_of([make_finding()])))
    assert report.status == AIFixStatus.NO_PROPOSAL
    assert "No AI provider" in report.errors[0]


def test_auto_selection_picks_highest_security_finding(repo: Path):
    low = make_finding(fingerprint="low", severity=Severity.LOW, start_line=7)
    high = make_finding()
    arch = make_finding(fingerprint="arch", category=FindingCategory.MAINTAINABILITY, severity=Severity.CRITICAL)
    provider = FakeProvider(answer(GOOD_EDITS))

    report = ai_fix_and_verify(
        repo,
        providers=[provider],
        scan=Scanner(scan_of([low, high, arch]), scan_of([low, high, arch]), scan_of([low, arch])),
    )

    assert report.finding_fingerprint == "fp-sql"


# --- real provider adapters with mocked clients -------------------------------


def test_gemini_adapter_requests_json():
    client = Mock()
    client.models.generate_content.return_value = SimpleNamespace(text='{"a": 1}')

    assert GeminiFixProvider(model="g", client=client).complete(system="s", user="u") == '{"a": 1}'
    config = client.models.generate_content.call_args.kwargs["config"]
    assert config.response_mime_type == "application/json"


def test_groq_adapter_requests_json_object():
    client = Mock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"a": 1}'))]
    )

    assert GroqFixProvider(model="q", client=client).complete(system="s", user="u") == '{"a": 1}'
    kwargs = client.chat.completions.create.call_args.kwargs
    assert kwargs["response_format"] == {"type": "json_object"}


def test_empty_adapter_answers_are_errors():
    client = Mock()
    client.models.generate_content.return_value = SimpleNamespace(text="")

    with pytest.raises(ValueError):
        GeminiFixProvider(model="g", client=client).complete(system="s", user="u")


def test_default_providers_follow_environment(monkeypatch):
    monkeypatch.delenv("SILENTSEC_AI_PROVIDERS", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    names = [type(provider).__name__ for provider in build_default_fix_providers()]
    assert names == ["OllamaFixProvider"]

    monkeypatch.setenv("GROQ_API_KEY", "test")
    providers = build_default_fix_providers()
    assert [type(provider).__name__ for provider in providers] == [
        "OllamaFixProvider",
        "GroqFixProvider",
    ]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_correlated_findings_from_other_tools_are_also_targets(repo: Path):
    semgrep = make_finding()
    bandit = make_finding(fingerprint="fp-bandit", tool="bandit", rule_id="B608")
    scanner = Scanner(scan_of([semgrep, bandit]), scan_of([semgrep, bandit]), scan_of([]))

    report = ai_fix_and_verify(
        repo, fingerprint="fp-sql", providers=[FakeProvider(answer(GOOD_EDITS))], scan=scanner
    )

    assert {item.fingerprint for item in report.verification.targets} == {"fp-sql", "fp-bandit"}
    assert report.verification.verdict == FixVerdict.VERIFIED_FIX
