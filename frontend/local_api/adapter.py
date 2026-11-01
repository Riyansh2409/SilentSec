"""The only module coupled to SilentSec's Python interfaces.

Keep backend-specific changes here; the HTTP and browser contracts are versioned
independently. Return backend model data without recomputing security scores.
"""

from __future__ import annotations

import importlib.metadata
import inspect
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


def provider_configuration() -> dict:
    """Use the backend's provider factory without making inference requests.

    Configured is distinct from reachable: no daemon is contacted and no models
    are downloaded. Locality follows the validated actual host, including an
    explicitly enabled remote Ollama server.
    """
    from silentsec.triage.factory import build_default_providers
    from silentsec.triage.ollama_provider import _is_loopback
    from silentsec.triage.sanitization import redact_sensitive_text

    providers = []
    instances = []
    try:
        instances = build_default_providers()
        for name, provider in instances:
            host = (
                getattr(getattr(provider, "_client", None), "host", None)
                if name == "ollama"
                else None
            )
            local = bool(host and _is_loopback(urlsplit(host).hostname or ""))
            providers.append(
                {
                    "name": name,
                    "model": str(getattr(provider, "model", "unknown")),
                    "scope": "local" if local else "external",
                }
            )
        return {
            "ai_configured": bool(providers),
            "ai_providers": providers,
            "ai_local_only": bool(providers) and all(p["scope"] == "local" for p in providers),
            "ai_configuration_error": None,
        }
    except Exception as exc:  # noqa: BLE001 - optional AI must not break scanning
        return {
            "ai_configured": False,
            "ai_providers": [],
            "ai_local_only": False,
            "ai_configuration_error": redact_sensitive_text(str(exc))[:700],
        }
    finally:
        for _, provider in instances:
            client = getattr(provider, "_client", None)
            # OllamaClient wraps httpx; closing it here does not contact the host.
            close = getattr(getattr(client, "_client", client), "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001, S110 - optional client cleanup
                    pass


def configure_backend(path: str) -> None:
    source = Path(path).resolve() / "src"
    if not (source / "silentsec" / "scanners" / "scanner_service.py").is_file():
        raise ValueError("Backend folder must contain src/silentsec/scanners/scanner_service.py.")
    sys.path.insert(0, str(source))


def interfaces():
    from silentsec.gate import run_gate
    from silentsec.history import build_timeline
    from silentsec.remediation.ai_fix import ai_fix_and_verify
    from silentsec.remediation.verify import verify_fix
    from silentsec.report import generate_report
    from silentsec.scanners.scanner_service import scan_repository

    return {
        "scan": scan_repository,
        "history": build_timeline,
        "verify": verify_fix,
        "fix": ai_fix_and_verify,
        "report": generate_report,
        "gate": run_gate,
    }


def probe() -> dict:
    operations = interfaces()
    required = {
        "scan": {"repo_path", "enable_ai_triage", "max_ai_triage_findings"},
        "history": {"repo_path", "commits", "database"},
        "verify": {"repo_root", "diff_text", "run_tests"},
        "fix": {"repo_root", "fingerprint", "run_tests"},
        "report": {"repo_path", "include_history", "fixes"},
        "gate": {"repo_path", "base", "head", "policy"},
    }
    compatible = {
        name: expected <= set(inspect.signature(operations[name]).parameters)
        for name, expected in required.items()
    }
    try:
        from silentsec.api.app import create_app

        routes = {route.path for route in create_app().routes}
        compatible.update(
            github=True,
            upload=True,
            verify_github="/api/verify/github" in routes,
            verify_upload="/api/verify/upload" in routes,
        )
    except ImportError:
        compatible.update(github=False, upload=False, verify_github=False, verify_upload=False)
    try:
        version = importlib.metadata.version("silentsec")
    except importlib.metadata.PackageNotFoundError:
        version = "source checkout"
    import silentsec

    backend = Path(silentsec.__file__).resolve().parents[2]
    commit = None
    try:
        git = subprocess.run(
            ["git", "-C", str(backend), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if git.returncode == 0:
            commit = git.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return {
        "version": version,
        "commit": commit,
        "capabilities": compatible,
        "scanners": {
            name: bool(shutil.which(name))
            for name in ("semgrep", "bandit", "gitleaks", "git", "osv-scanner")
        },
        **provider_configuration(),
    }


def run(operation: str, args: dict, directory: Path, data_root: Path) -> dict:
    if operation == "probe":
        import json

        result = probe()
        config_path = data_root / "config.json"
        if config_path.is_file():
            result["archive_revision"] = json.loads(
                config_path.read_text(encoding="utf-8-sig")
            ).get("archive_revision")
        return result
    if operation in {"github", "upload", "verify_github", "verify_upload"}:
        import asyncio
        import base64

        import httpx

        from silentsec.api.app import create_app

        async def native_scan():
            # Exercise the backend's own HTTP contract in-process; no extra public server.
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=create_app()), base_url="http://silentsec-local"
            ) as client:
                if operation == "verify_github":
                    response = await client.post(
                        "/api/verify/github",
                        json={
                            "url": args["url"],
                            "patch": args["patch"],
                            "targets": args.get("targets"),
                            "timeout_seconds": args.get("timeout", 180),
                        },
                    )
                elif operation == "verify_upload":
                    response = await client.post(
                        "/api/verify/upload",
                        files={
                            "file": (
                                args["filename"],
                                base64.b64decode(args["content"], validate=True),
                                "application/octet-stream",
                            ),
                            "patch": ("fix.diff", args["patch"].encode("utf-8"), "text/plain"),
                        },
                    )
                elif operation == "github":
                    response = await client.post(
                        "/api/scan/github",
                        json={
                            "url": args["url"],
                            "history_commits": args.get("commits", 0),
                            "timeout_seconds": args.get("timeout", 180),
                        },
                    )
                else:
                    content = base64.b64decode(args["content"], validate=True)
                    response = await client.post(
                        "/api/scan/upload",
                        files={"file": (args["filename"], content, "application/octet-stream")},
                    )
                if response.status_code != 200:
                    raise ValueError(str(response.json().get("detail", "Source scan failed.")))
                data = response.json()
                if operation.startswith("verify_"):
                    return data
                report = await client.get(data["report_url"])
                report.raise_for_status()
                (directory / "report.html").write_text(report.text, encoding="utf-8")
                return data

        return asyncio.run(native_scan())
    if operation == "context":
        from silentsec.context import build_source_context
        from silentsec.schemas import Finding

        return {
            "context": build_source_context(
                args["repo_path"],
                Finding.model_validate(args["finding"]),
                secret_findings=[
                    Finding.model_validate(item) for item in args.get("secret_findings", [])
                ],
            )
        }
    actions = interfaces()
    repo = args["repo_path"]
    timeout = args.get("timeout", 180)
    if operation == "gate":
        from silentsec.gate import GatePolicy
        from silentsec.schemas import Severity

        result = actions[operation](
            repo,
            base=args.get("base", "main"),
            head=args.get("head", "HEAD"),
            policy=GatePolicy(
                fail_on=Severity(args.get("fail_on", "high")),
                fail_on_architecture=args.get("fail_on_architecture", False),
                include_tests=args.get("include_tests", False),
            ),
            timeout_seconds=timeout,
        )
    elif operation == "scan":
        result = actions[operation](
            repo,
            timeout_seconds=timeout,
            enable_ai_triage=args.get("ai_triage", False),
            max_ai_triage_findings=args.get("max_ai_findings", 20),
            use_triage_cache=args.get("use_cache", True),
        )
    elif operation == "history":
        result = actions[operation](
            repo,
            commits=args.get("commits", 10),
            timeout_seconds=timeout,
            use_cache=args.get("use_cache", True),
            database=data_root / "history.sqlite",
        )
    elif operation == "verify":
        from silentsec.schemas import Severity

        result = actions[operation](
            repo,
            args["patch"],
            timeout_seconds=timeout,
            run_tests=args.get("run_tests", False),
            test_timeout_seconds=300,
            target_fingerprints=args.get("targets") or None,
            regression_severity=Severity.INFO if args.get("strict") else Severity.MEDIUM,
        )
    elif operation == "fix":
        result = actions[operation](
            repo,
            fingerprint=args.get("fingerprint") or None,
            run_tests=args.get("run_tests", False),
            timeout_seconds=timeout,
        )
    elif operation == "report":
        from silentsec.report import load_fix_report

        fixes = [load_fix_report(Path(p)) for p in args.get("fix_paths", [])]
        html, scan, timeline = actions[operation](
            repo,
            commits=args.get("commits", 10),
            include_history=args.get("include_history", False),
            fixes=fixes,
            enable_ai_triage=args.get("ai_triage", False),
            timeout_seconds=timeout,
        )
        (directory / "report.html").write_text(html, encoding="utf-8")
        return {
            "scan": scan.model_dump(mode="json"),
            "timeline": timeline.model_dump(mode="json") if timeline else None,
            "artifact": "report.html",
        }
    else:
        raise ValueError("Unsupported operation.")
    if operation in {"scan", "gate"}:
        import json

        from silentsec.report.sarif import gate_to_sarif, scan_to_sarif

        sarif = scan_to_sarif(result) if operation == "scan" else gate_to_sarif(result)
        (directory / "silentsec.sarif").write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return result.model_dump(mode="json")
