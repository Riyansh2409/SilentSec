"""Cached AI triage keeps who produced it (provider, model, local)."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from silentsec import cli
from silentsec.report import render_report
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import scan_repository
from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.triage import TriageResult, TriageRouter
from silentsec.triage.cache import TriageCache
from silentsec.triage.schemas import TriageAttribution


def make_finding(fingerprint: str = "fp-1") -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool="semgrep",
        rule_id="eval-exec",
        file_path="app.py",
        start_line=2,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message="eval is called with user input",
    )


def result_for(finding: Finding) -> TriageResult:
    return TriageResult(
        finding_id=finding.finding_id,
        fingerprint=finding.fingerprint,
        priority="high",
        summary="User input reaches eval.",
        rationale="eval executes arbitrary code.",
        remediation_steps=["Use ast.literal_eval."],
    )


class LocalModel:
    model = "qwen2.5-coder:7b"

    def __init__(self) -> None:
        self.calls = 0

    def triage(self, *, finding, context=""):
        self.calls += 1
        return result_for(finding)


OLLAMA = TriageAttribution(provider="ollama", model="qwen2.5-coder:7b", local=True)


# --- cache ---------------------------------------------------------------------


def test_cached_result_keeps_provider_model_and_local(tmp_path: Path):
    finding = make_finding()
    TriageCache(tmp_path).put("k", result_for(finding), OLLAMA)

    stored = json.loads((tmp_path / "k.json").read_text(encoding="utf-8"))
    # A new cache object reads the entry back from disk.
    result, attribution = TriageCache(tmp_path).get_with_attribution("k", finding=finding)

    assert (stored["provider"], stored["model"], stored["local"]) == (
        "ollama", "qwen2.5-coder:7b", True
    )
    assert result.fingerprint == "fp-1"
    assert attribution == TriageAttribution(
        provider="ollama", model="qwen2.5-coder:7b", local=True, cached=True
    )
    assert attribution.label == "ollama qwen2.5-coder:7b"


def test_legacy_entry_without_attribution_still_loads(tmp_path: Path):
    finding = make_finding()
    # Written before attribution was stored: only the TriageResult fields.
    legacy = result_for(finding).model_dump(mode="json")
    (tmp_path / "k.json").write_text(json.dumps(legacy), encoding="utf-8")
    cache = TriageCache(tmp_path)

    result, attribution = cache.get_with_attribution("k", finding=finding)

    assert result.summary == "User input reaches eval."
    assert attribution == TriageAttribution(cached=True)
    assert attribution.label is None
    assert cache.get("k", finding=finding) is not None  # the old API is unchanged


@pytest.mark.parametrize("bad", [{"provider": 123}, {"provider": ""}, {"local": [1]}])
def test_malformed_attribution_keeps_the_result_as_cached(tmp_path: Path, bad: dict):
    finding = make_finding()
    entry = result_for(finding).model_dump(mode="json") | {"model": "m"} | bad
    (tmp_path / "k.json").write_text(json.dumps(entry), encoding="utf-8")

    result, attribution = TriageCache(tmp_path).get_with_attribution("k", finding=finding)

    assert result.fingerprint == "fp-1"
    assert attribution == TriageAttribution(cached=True)


def test_a_model_reply_cannot_claim_attribution():
    finding = make_finding()
    reply = result_for(finding).model_dump(mode="json") | {"provider": "ollama", "local": True}

    # Attribution lives outside TriageResult, which rejects unknown fields.
    with pytest.raises(ValidationError):
        TriageResult.model_validate(reply)


def test_router_cache_hit_reports_the_original_provider(tmp_path: Path):
    model = LocalModel()
    router = TriageRouter([("ollama", model)], cache=TriageCache(tmp_path))
    finding = make_finding()

    router.triage(finding=finding)
    fresh = router.last_attribution
    router.triage(finding=finding)
    cached = router.last_attribution

    assert model.calls == 1
    assert fresh == OLLAMA
    assert cached == OLLAMA.model_copy(update={"cached": True})


# --- CLI and report ------------------------------------------------------------


def make_result(scanner: str, findings=None) -> ScannerRunResult:
    return ScannerRunResult(
        scanner=scanner, status=ScannerStatus.SUCCESS, findings=findings or [], duration_seconds=0
    )


def scan(repo: Path, cache_dir: Path):
    router = TriageRouter([("ollama", LocalModel())], cache=TriageCache(cache_dir))
    with (
        patch("silentsec.scanners.scanner_service.run_semgrep",
              return_value=make_result("semgrep", [make_finding()])),
        patch("silentsec.scanners.scanner_service.run_bandit", return_value=make_result("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks",
              return_value=make_result("gitleaks")),
        patch("silentsec.scanners.scanner_service.run_architecture_analyzer",
              return_value=make_result("architecture")),
        patch("silentsec.scanners.scanner_service.run_osv_scanner", return_value=make_result("osv")),
        patch("silentsec.scanners.scanner_service.build_default_router", return_value=router),
    ):
        return scan_repository(repo, enable_ai_triage=True)


def outputs(report) -> tuple[str, str]:
    document = render_report(report, repo_name="demo", generated_at=datetime(2026, 10, 31, 12))
    return cli.format_summary(report), document


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_bytes(b"x = input()\neval(x)\n")
    return root


def test_cached_run_shows_the_same_attribution_as_a_fresh_run(repo: Path, tmp_path: Path):
    fresh_text, fresh_html = outputs(scan(repo, tmp_path / "cache"))
    cached_report = scan(repo, tmp_path / "cache")
    cached_text, cached_html = outputs(cached_report)

    line = "<b>AI triage</b> by ollama qwen2.5-coder:7b, local (suggested priority high"
    assert line in fresh_html and line in cached_html
    assert cached_report.triage_cache_hits == 1
    assert "(ollama qwen2.5-coder:7b: 1; 0 from cache" in fresh_text
    assert "(ollama qwen2.5-coder:7b: 1; 1 from cache, 0 provider calls)" in cached_text


def test_legacy_cache_entry_is_shown_as_cached(repo: Path, tmp_path: Path):
    cache_dir = tmp_path / "cache"
    scan(repo, cache_dir)
    # Turn the stored entry into one written before attribution existed.
    [entry_file] = list(cache_dir.glob("*.json"))
    entry = json.loads(entry_file.read_text(encoding="utf-8"))
    for name in ("provider", "model", "local"):
        entry.pop(name)
    entry_file.write_text(json.dumps(entry), encoding="utf-8")

    text, document = outputs(scan(repo, cache_dir))

    assert "<b>AI triage (cached)</b> (suggested priority high" in document
    assert " by " not in document.split("AI triage (cached)")[1][:40]
    assert "(provider unknown (cached): 1; 1 from cache" in text
