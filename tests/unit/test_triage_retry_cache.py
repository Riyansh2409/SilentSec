"""Bounded retries, caching, and call budgets for the triage router."""

import json
from pathlib import Path

import pytest

from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.triage import factory
from silentsec.triage.cache import PROMPT_VERSION, TriageCache, cache_key, default_cache
from silentsec.triage.router import TriageBudgetExceededError, TriageRouter, TriageRoutingError
from silentsec.triage.schemas import TriagePriority, TriageResult


def make_finding(**overrides) -> Finding:
    values = {
        "fingerprint": "fp-1",
        "tool": "semgrep",
        "rule_id": "R1",
        "file_path": "app.py",
        "start_line": 5,
        "category": FindingCategory.SECURITY,
        "severity": Severity.HIGH,
        "message": "Potential issue",
    }
    values.update(overrides)
    return Finding(**values)


def result_for(finding: Finding) -> TriageResult:
    return TriageResult(
        finding_id=finding.finding_id,
        fingerprint=finding.fingerprint,
        priority=TriagePriority.HIGH,
        summary="Risky call",
        rationale="Evidence from context.",
        remediation_steps=["Use a safe API."],
        requires_human_review=True,
    )


class HttpError(Exception):
    def __init__(self, status_code: int):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


class ScriptedProvider:
    """Raises the scripted errors in order, then returns a valid result."""

    def __init__(self, *errors: Exception, model: str = "m1"):
        self.errors = list(errors)
        self.calls = 0
        self.model = model

    def triage(self, *, finding, context=""):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return result_for(finding)


def no_sleep(delays: list[float]):
    return delays.append


# --- retries ----------------------------------------------------------------


@pytest.mark.parametrize("error", [TimeoutError("t"), ConnectionError("c"), HttpError(429), HttpError(503)])
def test_transient_error_is_retried_on_same_provider(error):
    provider = ScriptedProvider(error)
    backup = ScriptedProvider()
    delays: list[float] = []
    router = TriageRouter(
        [("primary", provider), ("backup", backup)], max_retries=1, sleep=no_sleep(delays)
    )

    router.triage(finding=make_finding())

    assert provider.calls == 2
    assert backup.calls == 0
    assert delays == [0.5]


@pytest.mark.parametrize("error", [HttpError(401), HttpError(400), ValueError("bad json")])
def test_auth_and_invalid_output_errors_are_not_retried(error):
    provider = ScriptedProvider(error)
    backup = ScriptedProvider()
    router = TriageRouter(
        [("primary", provider), ("backup", backup)], max_retries=3, sleep=no_sleep([])
    )

    router.triage(finding=make_finding())

    assert provider.calls == 1
    assert backup.calls == 1


def test_retries_are_bounded_and_backoff_grows():
    provider = ScriptedProvider(*(TimeoutError("t") for _ in range(10)))
    delays: list[float] = []
    router = TriageRouter([("only", provider)], max_retries=2, sleep=no_sleep(delays))

    with pytest.raises(TriageRoutingError):
        router.triage(finding=make_finding())

    assert provider.calls == 3
    assert delays == [0.5, 1.0]


def test_default_router_does_not_retry():
    provider = ScriptedProvider(TimeoutError("t"))
    backup = ScriptedProvider()

    TriageRouter([("primary", provider), ("backup", backup)]).triage(finding=make_finding())

    assert provider.calls == 1


@pytest.mark.parametrize("value", [-1, 6])
def test_retry_limit_is_validated(value):
    with pytest.raises(ValueError):
        TriageRouter([("p", ScriptedProvider())], max_retries=value)


def test_factory_enables_one_retry(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    router = factory.build_default_router(cache=None)

    assert router is not None
    assert router._max_retries == factory.DEFAULT_MAX_RETRIES == 1


# --- budget -----------------------------------------------------------------


def test_call_budget_stops_further_provider_calls():
    provider = ScriptedProvider()
    router = TriageRouter([("p", provider)], max_provider_calls=2)

    router.triage(finding=make_finding(fingerprint="a"))
    router.triage(finding=make_finding(fingerprint="b"))
    with pytest.raises(TriageBudgetExceededError):
        router.triage(finding=make_finding(fingerprint="c"))

    assert provider.calls == 2


def test_retries_count_against_the_budget():
    provider = ScriptedProvider(TimeoutError("t"), TimeoutError("t"))
    router = TriageRouter(
        [("p", provider)], max_retries=5, max_provider_calls=2, sleep=no_sleep([])
    )

    with pytest.raises(TriageBudgetExceededError):
        router.triage(finding=make_finding())

    assert provider.calls == 2


# --- cache ------------------------------------------------------------------


def test_cache_hit_skips_provider_and_rebinds_finding_id():
    cache = TriageCache()
    provider = ScriptedProvider()
    router = TriageRouter([("p", provider)], cache=cache)

    first_scan = make_finding()
    second_scan = make_finding()  # same fingerprint, new finding_id
    assert first_scan.finding_id != second_scan.finding_id

    router.triage(finding=first_scan)
    cached = router.triage(finding=second_scan)

    assert provider.calls == 1
    assert cache.hits == 1
    assert cached.finding_id == second_scan.finding_id
    assert cached.fingerprint == second_scan.fingerprint


def test_cache_misses_when_context_changes():
    provider = ScriptedProvider()
    router = TriageRouter([("p", provider)], cache=TriageCache())

    router.triage(finding=make_finding(), context="1: x = 1")
    router.triage(finding=make_finding(), context="1: x = 2")

    assert provider.calls == 2


def test_cache_misses_when_model_changes():
    cache = TriageCache()
    TriageRouter([("p", ScriptedProvider(model="m1"))], cache=cache).triage(finding=make_finding())
    provider = ScriptedProvider(model="m2")

    TriageRouter([("p", provider)], cache=cache).triage(finding=make_finding())

    assert provider.calls == 1


def test_failed_triage_is_not_cached():
    cache = TriageCache()
    router = TriageRouter([("p", ScriptedProvider(ValueError("bad")))], cache=cache)

    with pytest.raises(TriageRoutingError):
        router.triage(finding=make_finding())

    provider = ScriptedProvider()
    TriageRouter([("p", provider)], cache=cache).triage(finding=make_finding())
    assert provider.calls == 1


def test_cache_key_uses_only_sanitized_inputs_and_prompt_version():
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    finding = make_finding()
    provider = ScriptedProvider()
    cache = TriageCache()
    router = TriageRouter([("p", provider)], cache=cache)

    router.triage(finding=finding, context=f"1: token = '{secret}'")

    stored = json.dumps(cache._memory)
    assert secret not in stored
    assert PROMPT_VERSION
    key = cache_key(
        finding=finding, sanitized_message="m", sanitized_context="c", provider_signature="s"
    )
    assert len(key) == 64


def test_disk_cache_survives_a_new_process(tmp_path: Path):
    TriageRouter([("p", ScriptedProvider())], cache=TriageCache(tmp_path)).triage(
        finding=make_finding()
    )
    assert list(tmp_path.glob("*.json"))

    provider = ScriptedProvider()
    fresh = TriageCache(tmp_path)
    TriageRouter([("p", provider)], cache=fresh).triage(finding=make_finding())

    assert provider.calls == 0
    assert fresh.hits == 1


def test_corrupted_disk_entry_is_a_miss(tmp_path: Path):
    cache = TriageCache(tmp_path)
    TriageRouter([("p", ScriptedProvider())], cache=cache).triage(finding=make_finding())
    for entry in tmp_path.glob("*.json"):
        entry.write_text("{not json", encoding="utf-8")

    provider = ScriptedProvider()
    TriageRouter([("p", provider)], cache=TriageCache(tmp_path)).triage(finding=make_finding())

    assert provider.calls == 1


def test_cache_entry_with_other_fingerprint_is_rejected(tmp_path: Path):
    cache = TriageCache()
    finding = make_finding()
    cache.put("k", result_for(make_finding(fingerprint="other")))

    assert cache.get("k", finding=finding) is None


def test_default_cache_honours_environment(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SILENTSEC_TRIAGE_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("SILENTSEC_TRIAGE_CACHE", raising=False)
    assert default_cache().directory == tmp_path

    monkeypatch.setenv("SILENTSEC_TRIAGE_CACHE", "off")
    assert default_cache() is None
