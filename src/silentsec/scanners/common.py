
import re
from hashlib import sha256
from pathlib import Path

from silentsec.schemas import Severity


def normalize_severity(value: object) -> Severity:
    raw = str(value or "").strip().upper()

    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "ERROR": Severity.HIGH,
        "HIGH": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "UNDEFINED": Severity.INFO,
    }
    return mapping.get(raw, Severity.MEDIUM)


def normalize_confidence(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if 0 <= value <= 1:
            return float(value)
        return None

    mapping = {
        "HIGH": 0.9,
        "MEDIUM": 0.6,
        "LOW": 0.3,
    }
    return mapping.get(str(value or "").strip().upper())


def extract_cwe(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("id") or value.get("cwe") or value.get("name")

    if isinstance(value, int):
        return f"CWE-{value}"

    if isinstance(value, list):
        for item in value:
            found = extract_cwe(item)
            if found:
                return found
        return None

    if value is None:
        return None

    text = str(value)

    if text.isdigit():
        return f"CWE-{text}"

    match = re.search(r"\bCWE-\d+\b", text, flags=re.IGNORECASE)
    return match.group(0).upper() if match else None


def normalize_file_path(root: Path, raw_path: str) -> str:
    root = root.resolve()
    raw_text = str(raw_path).replace("\\", "/")

    while raw_text.startswith("./"):
        raw_text = raw_text[2:]

    if raw_text.startswith(f"{root.name}/"):
        raw_text = raw_text[len(root.name) + 1 :]

    path = Path(raw_text)

    candidate = path if path.is_absolute() else root / path

    try:
        return candidate.resolve().relative_to(root).as_posix()
    except ValueError:
        # Preserve the scanner's path for diagnostics if it is outside root.
        return raw_text


def create_fingerprint(
    tool: str,
    rule_id: str,
    file_path: str,
    line_number: int,
) -> str:
    value = f"{tool}|{rule_id}|{file_path}|{line_number}"
    return sha256(value.encode("utf-8")).hexdigest()
