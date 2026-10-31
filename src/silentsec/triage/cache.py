"""Cache AI triage results so repeated scans do not spend API quota again.

A cache entry is keyed by:

- the finding fingerprint (tool, rule, file, line);
- a hash of the SANITIZED finding message and source context, so a code
  change around the finding produces a new key;
- PROMPT_VERSION, bumped whenever the triage prompt or schema changes;
- the provider chain (names and models), so switching models misses.

Only sanitized inputs are hashed; raw secrets never reach the cache key.
Cached values are validated TriageResult objects. The finding_id is
replaced on read, because finding IDs are generated fresh for each scan.
"""

import json
import os
import tempfile
from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError

from silentsec.schemas.finding import Finding

from .schemas import TriageAttribution, TriageResult

# Bump when the triage prompt, rules, or TriageResult schema change.
PROMPT_VERSION = "triage-v1"
# Stored next to the result fields: who produced the result.
ATTRIBUTION_KEYS = ("provider", "model", "local")

CACHE_DIR_ENV = "SILENTSEC_TRIAGE_CACHE_DIR"
CACHE_DISABLE_ENV = "SILENTSEC_TRIAGE_CACHE"


def cache_key(
    *,
    finding: Finding,
    sanitized_message: str,
    sanitized_context: str,
    provider_signature: str,
) -> str:
    """Build a stable cache key from sanitized inputs only."""
    content_hash = sha256(
        json.dumps([sanitized_message, sanitized_context]).encode("utf-8")
    ).hexdigest()
    material = json.dumps(
        [finding.fingerprint, content_hash, PROMPT_VERSION, provider_signature]
    )
    return sha256(material.encode("utf-8")).hexdigest()


class TriageCache:
    """In-memory cache with optional on-disk persistence (one file per key)."""

    def __init__(self, directory: str | Path | None = None) -> None:
        self._memory: dict[str, dict] = {}
        self._directory = Path(directory).expanduser() if directory else None
        self.hits = 0
        self.misses = 0

    @property
    def directory(self) -> Path | None:
        return self._directory

    def _path(self, key: str) -> Path:
        assert self._directory is not None
        return self._directory / f"{key}.json"

    def get(self, key: str, *, finding: Finding) -> TriageResult | None:
        """Return a cached result rebound to this finding, or None."""
        cached = self.get_with_attribution(key, finding=finding)
        return cached[0] if cached is not None else None

    def get_with_attribution(
        self, key: str, *, finding: Finding
    ) -> tuple[TriageResult, TriageAttribution] | None:
        """Like get(), plus who produced the result (cached=True).

        Entries written before attribution was stored have no provider; their
        attribution has provider=None.
        """
        payload = self._memory.get(key)

        if payload is None and self._directory is not None:
            try:
                payload = json.loads(self._path(key).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                payload = None

        if not isinstance(payload, dict):
            self.misses += 1
            return None

        # Attribution keys sit next to the result fields; take them out first,
        # because TriageResult rejects unknown fields.
        fields = {name: value for name, value in payload.items() if name not in ATTRIBUTION_KEYS}
        try:
            attribution = TriageAttribution.model_validate(
                {name: payload[name] for name in ATTRIBUTION_KEYS if name in payload}
                | {"cached": True}
            )
        except ValidationError:
            # Malformed attribution: keep the result, show it as "cached".
            attribution = TriageAttribution(cached=True)

        try:
            result = TriageResult.model_validate(
                {**fields, "finding_id": finding.finding_id}
            )
        except ValidationError:
            # A corrupted or outdated entry is a miss, never an error.
            self.misses += 1
            return None

        if result.fingerprint != finding.fingerprint or not result.requires_human_review:
            self.misses += 1
            return None

        self._memory[key] = payload
        self.hits += 1
        return result, attribution

    def put(
        self, key: str, result: TriageResult, attribution: TriageAttribution | None = None
    ) -> None:
        """Store a validated result, and who produced it.

        Disk errors are ignored: caching is best-effort.
        """
        payload = result.model_dump(mode="json")
        if attribution is not None and attribution.provider is not None:
            payload |= {
                "provider": attribution.provider,
                "model": attribution.model,
                "local": attribution.local,
            }
        self._memory[key] = payload

        if self._directory is None:
            return

        try:
            self._directory.mkdir(parents=True, exist_ok=True)
            # Write atomically so a crash never leaves a half-written entry.
            descriptor, temporary = tempfile.mkstemp(
                dir=self._directory, prefix=".tmp-", suffix=".json"
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            os.replace(temporary, self._path(key))
        except OSError:
            return


def default_cache() -> TriageCache | None:
    """Build the cache configured by the environment.

    SILENTSEC_TRIAGE_CACHE=off disables caching. SILENTSEC_TRIAGE_CACHE_DIR
    sets the directory; otherwise ~/.cache/silentsec/triage is used.
    """
    if os.getenv(CACHE_DISABLE_ENV, "").strip().lower() in {"0", "off", "false", "no"}:
        return None

    directory = os.getenv(CACHE_DIR_ENV, "").strip()
    return TriageCache(directory or Path.home() / ".cache" / "silentsec" / "triage")
