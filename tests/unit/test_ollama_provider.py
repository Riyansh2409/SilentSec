"""Ollama (local LLM) provider. httpx is mocked; no real Ollama is needed."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from pydantic import ValidationError

from silentsec import cli
from silentsec.remediation.ai_fix import propose_fix
from silentsec.remediation.fix_providers import (
    FIX_SYSTEM_PROMPT,
    OllamaFixProvider,
    build_default_fix_providers,
)
from silentsec.report import render_report
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import scan_repository
from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.triage import TriageResult, TriageRouter
from silentsec.triage.chat_prompt import TRIAGE_SYSTEM_PROMPT
from silentsec.triage.factory import build_default_providers
from silentsec.triage.ollama_provider import (
    OllamaClient,
    OllamaTriageProvider,
    validate_host,
)
from silentsec.triage.providers import (
    AIProviderConfigError,
    ProviderUnavailableError,
    configured_provider_order,
)

ENV_VARS = (
    "SILENTSEC_AI_PROVIDERS",
    "SILENTSEC_OLLAMA_ALLOW_REMOTE",
    "OLLAMA_HOST",
    "OLLAMA_MODEL",
    "OLLAMA_TIMEOUT",
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def make_finding(fingerprint: str = "ollama-fp", line: int = 2) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool="semgrep",
        rule_id="eval-exec",
        file_path="app.py",
        start_line=line,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message="eval is called with user input",
    )


def triage_payload(finding: Finding) -> dict:
    return {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "priority": "high",
        "summary": "User input reaches eval.",
        "rationale": "eval executes arbitrary code.",
        "remediation_steps": "Use ast.literal_eval instead.",  # a string is normalized to a list
        "evidence": ["app.py line 2"],
        "limitations": [],
        "requires_human_review": True,
    }


def ollama_client(handler, **settings) -> OllamaClient:
    return OllamaClient(transport=httpx.MockTransport(handler), **settings)


def reply(content: str) -> httpx.Response:
    return httpx.Response(200, json={"message": {"role": "assistant", "content": content}})


def refused(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


# --- triage provider --------------------------------------------------------


def test_valid_reply_is_parsed_into_a_triage_result():
    finding = make_finding()
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append({"url": str(request.url), "body": json.loads(request.content)})
        return reply(json.dumps(triage_payload(finding)))

    provider = OllamaTriageProvider(client=ollama_client(handler))
    result = provider.triage(finding=finding, context="1 | x = input()\n2 | eval(x)")

    assert isinstance(result, TriageResult)
    assert result.fingerprint == "ollama-fp" and result.priority.value == "high"
    assert result.remediation_steps == ["Use ast.literal_eval instead."]
    assert provider.model == "qwen2.5-coder:7b"

    body = seen[0]["body"]
    assert seen[0]["url"] == "http://localhost:11434/api/chat"
    assert body["model"] == "qwen2.5-coder:7b"
    assert body["stream"] is False and body["format"] == "json"
    assert body["options"] == {"temperature": 0}
    # The same system prompt as the other chat provider (Groq).
    assert body["messages"][0] == {"role": "system", "content": TRIAGE_SYSTEM_PROMPT}
    assert json.loads(body["messages"][1]["content"])["finding"]["fingerprint"] == "ollama-fp"


def test_invalid_json_is_rejected():
    provider = OllamaTriageProvider(client=ollama_client(lambda request: reply("not json {")))

    with pytest.raises(ValueError, match="Ollama returned invalid JSON"):
        provider.triage(finding=make_finding())


def test_reply_that_fails_the_schema_is_rejected():
    finding = make_finding()
    bad = {**triage_payload(finding), "priority": "urgent", "extra": "field"}
    provider = OllamaTriageProvider(client=ollama_client(lambda request: reply(json.dumps(bad))))

    with pytest.raises(ValidationError):
        provider.triage(finding=finding)


def test_ollama_not_running_is_a_clear_error():
    provider = OllamaTriageProvider(client=ollama_client(refused))

    with pytest.raises(ProviderUnavailableError) as raised:
        provider.triage(finding=make_finding())

    assert str(raised.value) == (
        "Ollama is not running at http://localhost:11434. "
        "Start it or remove it from SILENTSEC_AI_PROVIDERS."
    )


def test_missing_model_says_how_to_pull_it():
    provider = OllamaTriageProvider(
        client=ollama_client(lambda request: httpx.Response(404, json={"error": "not found"}))
    )

    with pytest.raises(ProviderUnavailableError, match="Run: ollama pull qwen2.5-coder:7b"):
        provider.triage(finding=make_finding())


def test_timeout_and_model_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1:8b")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "30")
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11500/")

    client = ollama_client(lambda request: reply("{}"))

    assert (client.model, client.timeout_seconds, client.host) == (
        "llama3.1:8b", 30.0, "http://127.0.0.1:11500"
    )
    monkeypatch.setenv("OLLAMA_TIMEOUT", "soon")
    with pytest.raises(AIProviderConfigError, match="OLLAMA_TIMEOUT"):
        ollama_client(lambda request: reply("{}"))


# --- host safety --------------------------------------------------------------


@pytest.mark.parametrize(
    "host", ["http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"]
)
def test_loopback_hosts_are_allowed(host):
    assert validate_host(host, allow_remote=False) == host


@pytest.mark.parametrize(
    "host",
    [
        "http://192.168.1.20:11434",
        "https://ollama.example.com",
        "http://localhost.example.com:11434",
        "http://0.0.0.0:11434",
    ],
)
def test_non_loopback_host_is_rejected_unless_allowed(host, monkeypatch):
    with pytest.raises(AIProviderConfigError, match="SILENTSEC_OLLAMA_ALLOW_REMOTE=1"):
        validate_host(host, allow_remote=False)

    monkeypatch.setenv("OLLAMA_HOST", host)
    with pytest.raises(AIProviderConfigError):
        OllamaClient()
    monkeypatch.setenv("SILENTSEC_OLLAMA_ALLOW_REMOTE", "1")
    assert OllamaClient().host == host


@pytest.mark.parametrize("host", ["localhost:11434", "ftp://localhost", "http://localhost/api"])
def test_malformed_hosts_are_rejected(host):
    with pytest.raises(AIProviderConfigError, match="OLLAMA_HOST"):
        validate_host(host, allow_remote=True)


def test_requests_ignore_proxy_settings(monkeypatch):
    # A proxy could carry code off the machine even for a localhost URL.
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.com:8080")
    client = OllamaClient()

    assert client._client._trust_env is False


# --- provider order -------------------------------------------------------------


def test_order_parsing(monkeypatch):
    assert configured_provider_order() is None

    monkeypatch.setenv("SILENTSEC_AI_PROVIDERS", " Ollama, groq,,gemini, ollama ")
    assert configured_provider_order() == ["ollama", "groq", "gemini"]


@pytest.mark.parametrize("value", ["ollama,openai", "claude", " , "])
def test_unknown_or_empty_names_are_a_clear_error(value, monkeypatch):
    monkeypatch.setenv("SILENTSEC_AI_PROVIDERS", value)

    with pytest.raises(AIProviderConfigError, match="SILENTSEC_AI_PROVIDERS"):
        configured_provider_order()


def test_default_order_is_unchanged_and_never_includes_ollama(monkeypatch):
    assert build_default_providers() == []

    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    monkeypatch.setenv("GROQ_API_KEY", "q-key")
    names = [name for name, _ in build_default_providers()]

    assert names == ["gemini-primary", "gemini-fallback", "groq"]


def test_listed_order_is_used_and_missing_keys_are_skipped(monkeypatch):
    monkeypatch.setenv("SILENTSEC_AI_PROVIDERS", "ollama,gemini,groq")
    monkeypatch.setenv("GROQ_API_KEY", "q-key")

    names = [name for name, _ in build_default_providers()]
    fix_names = [provider.name for provider in build_default_fix_providers()]

    assert names == ["ollama", "groq"]  # no GEMINI_API_KEY
    assert fix_names == ["ollama:qwen2.5-coder:7b", "groq:openai/gpt-oss-20b"]


def test_cache_key_differs_per_provider_and_model():
    def router(model: str) -> TriageRouter:
        return TriageRouter([("ollama", OllamaTriageProvider(client=OllamaClient(model=model)))])

    assert router("a:1").provider_signature == "ollama:a:1"
    assert router("a:1").provider_signature != router("b:1").provider_signature


# --- fallback and output ----------------------------------------------------------


class CloudProvider:
    model = "cloud-model"

    def triage(self, *, finding, context=""):
        payload = {**triage_payload(finding), "remediation_steps": ["Use ast.literal_eval."]}
        return TriageResult.model_validate(payload)


def make_result(scanner: str, findings=None) -> ScannerRunResult:
    return ScannerRunResult(
        scanner=scanner, status=ScannerStatus.SUCCESS, findings=findings or [], duration_seconds=0
    )


def scan_with_router(tmp_path: Path, router: TriageRouter, findings: list[Finding]):
    (tmp_path / "app.py").write_bytes(b"x = input()\neval(x)\n")
    with (
        patch("silentsec.scanners.scanner_service.run_semgrep",
              return_value=make_result("semgrep", findings)),
        patch("silentsec.scanners.scanner_service.run_bandit", return_value=make_result("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks",
              return_value=make_result("gitleaks")),
        patch("silentsec.scanners.scanner_service.run_architecture_analyzer",
              return_value=make_result("architecture")),
        patch("silentsec.scanners.scanner_service.run_osv_scanner", return_value=make_result("osv")),
        patch("silentsec.scanners.scanner_service.build_default_router", return_value=router),
    ):
        return scan_repository(tmp_path, enable_ai_triage=True)


def test_ollama_not_running_falls_back_and_the_scan_continues(tmp_path: Path):
    sleeps: list[float] = []
    router = TriageRouter(
        [("ollama", OllamaTriageProvider(client=ollama_client(refused))), ("groq", CloudProvider())],
        max_retries=1,
        sleep=sleeps.append,
    )
    findings = [make_finding("fp-1"), make_finding("fp-2", line=1)]

    report = scan_with_router(tmp_path, router, findings)

    assert len(report.triage_results) == 2
    assert {fp: item.label for fp, item in report.triage_providers.items()} == {
        "fp-1": "groq cloud-model", "fp-2": "groq cloud-model"
    }
    # Shown once, and not retried: a server that is not running will not start.
    assert report.triage_errors == [
        (
            "Ollama is not running at http://localhost:11434. "
            "Start it or remove it from SILENTSEC_AI_PROVIDERS."
        )
    ]
    assert sleeps == []
    assert report.security_debt is not None


def test_cli_and_report_name_the_provider_and_say_local(tmp_path: Path):
    finding = make_finding("fp-1")
    router = TriageRouter([("ollama", OllamaTriageProvider(
        client=ollama_client(lambda request: reply(json.dumps(triage_payload(finding)))),
    ))])

    report = scan_with_router(tmp_path, router, [finding])
    text = cli.format_summary(report)
    document = render_report(report, repo_name="demo", generated_at=datetime(2026, 10, 31, 12))

    assert "AI triage: 1 findings triaged (ollama qwen2.5-coder:7b: 1; 0 from cache" in text
    assert "<b>AI triage</b> by ollama qwen2.5-coder:7b, local (suggested priority high" in document


def test_unknown_provider_name_is_shown_in_the_scan(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SILENTSEC_AI_PROVIDERS", "ollama,chatgpt")
    (tmp_path / "app.py").write_bytes(b"x = 1\n")
    with (
        patch("silentsec.scanners.scanner_service.run_semgrep",
              return_value=make_result("semgrep", [make_finding()])),
        patch("silentsec.scanners.scanner_service.run_bandit", return_value=make_result("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks",
              return_value=make_result("gitleaks")),
        patch("silentsec.scanners.scanner_service.run_architecture_analyzer",
              return_value=make_result("architecture")),
        patch("silentsec.scanners.scanner_service.run_osv_scanner", return_value=make_result("osv")),
    ):
        report = scan_repository(tmp_path, enable_ai_triage=True)

    assert report.triage_errors[0].startswith(
        "Could not initialize AI triage: Unknown AI provider 'chatgpt'"
    )
    assert report.security_debt is not None


# --- fix provider ---------------------------------------------------------------------


def test_fix_provider_happy_path(tmp_path: Path):
    (tmp_path / "app.py").write_bytes(b"x = input()\nresult = eval(x)\nprint(result)\n")
    finding = make_finding(line=2)
    answer = {
        "fingerprint": finding.fingerprint,
        "explanation": "literal_eval only accepts literals.",
        "edits": [{"start_line": 2, "end_line": 2, "replacement": "result = ast.literal_eval(x)"}],
    }
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return reply(json.dumps(answer))

    provider = OllamaFixProvider(client=ollama_client(handler))
    proposal, errors = propose_fix(tmp_path, finding, [provider])

    assert errors == []
    assert proposal is not None and proposal.provider == "ollama:qwen2.5-coder:7b"
    assert "+result = ast.literal_eval(x)" in proposal.diff_text
    assert seen[0]["messages"][0] == {"role": "system", "content": FIX_SYSTEM_PROMPT}
    assert seen[0]["format"] == "json"


def test_fix_falls_back_when_ollama_is_not_running(tmp_path: Path):
    (tmp_path / "app.py").write_bytes(b"x = input()\nresult = eval(x)\n")
    finding = make_finding(line=2)

    class Declines:
        name = "groq:m"
        model = "m"

        def complete(self, *, system, user):
            return json.dumps({"fingerprint": finding.fingerprint, "explanation": "no", "edits": []})

    proposal, errors = propose_fix(
        tmp_path, finding, [OllamaFixProvider(client=ollama_client(refused)), Declines()]
    )

    assert proposal is None
    assert errors[0] == (
        "ollama:qwen2.5-coder:7b: Ollama is not running at http://localhost:11434. "
        "Start it or remove it from SILENTSEC_AI_PROVIDERS."
    )
    assert errors[1].startswith("groq:m: declined")
