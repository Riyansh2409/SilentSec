"""Leased DB jobs executed in bounded subprocesses, separate from the HTTP server."""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from silentsec.process import _kill_tree
from silentsec.remediation.sandbox import sanitized_environment

from . import jobs
from .models import (
    EntitlementSnapshot,
    OperationRequest,
    OperationResult,
    ScanJob,
    WorkstationRepository,
    now,
)


def scanner_path():
    tools = Path(__file__).resolve().parents[3] / "frontend" / ".tools"
    return os.pathsep.join(
        [str(Path(sys.executable).parent), str(tools), os.environ.get("PATH", "")]
    )


def execute(factory, settings, claim, stop=None):
    try:
        return _execute(factory, settings, claim, stop)
    except (OSError, ValueError, KeyError):
        jobs.finish(factory, *claim, error="operation_preparation_failed")


def _execute(factory, settings, claim, stop=None):
    job_id, token = claim
    with factory() as db:
        job = db.get(ScanJob, job_id)
        limits = db.get(EntitlementSnapshot, job.snapshot_id).limits
        request = {
            "kind": job.source_kind,
            "reference": job.source_reference,
            "name": job.source_name,
            "limits": limits,
        }
        if job.source_kind == "workstation":
            op = db.get(OperationRequest, job.id)
            if not op or op.organization_id != job.organization_id:
                raise ValueError("Invalid operation")
            request.update(operation=op.operation, args=dict(op.arguments))
            request["args"].pop("_units", None)
            if op.repository_id:
                repository = db.get(WorkstationRepository, op.repository_id)
                if (
                    not settings.workstation_enabled
                    or settings.environment == "production"
                    or not repository
                    or not repository.enabled
                    or repository.organization_id != job.organization_id
                    or Path(repository.root_path).resolve() != Path(repository.root_path)
                ):
                    raise ValueError("Repository unavailable")
                request["args"]["repo_path"] = repository.root_path
            if op.input_ref:
                private = settings.data_dir.resolve() / "inbox" / (op.input_ref + ".payload")
                request["args"].update(json.loads(private.read_text(encoding="utf-8")))
            request["fixes"] = []
            for fix_id in request["args"].pop("fix_job_ids", []):
                fix = db.get(OperationResult, fix_id)
                fix_op = db.get(OperationRequest, fix_id)
                if (
                    not fix
                    or fix.organization_id != job.organization_id
                    or fix.expires_at <= now()
                    or not fix_op
                    or fix_op.repository_id != op.repository_id
                ):
                    raise ValueError("Fix report unavailable")
                request["fixes"].append(fix.payload)
            cache = settings.data_dir.resolve() / "workstation-cache" / job.organization_id
            cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            request["cache"] = str(cache)
    inbox = settings.data_dir.resolve() / "inbox"
    if job.source_kind == "upload" and not Path(job.source_reference).resolve().is_relative_to(
        inbox
    ):
        jobs.finish(factory, job_id, token, error="invalid_source_reference")
        return
    try:
        with tempfile.TemporaryDirectory(prefix="ssec-job-") as temp:
            workspace = Path(temp)
            request_file, result_file, started = [
                workspace / name for name in ("request.json", "result.json", "started")
            ]
            request_file.write_text(json.dumps(request), encoding="utf-8")
            env = {
                key: value
                for key, value in sanitized_environment().items()
                if not key.upper().startswith(("SILENTSEC_", "PYTHON", "OLLAMA", "GIT_"))
            }
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
            env["PYTHONNOUSERSITE"] = "1"
            env["PATH"] = scanner_path()
            env["TEMP"] = env["TMP"] = str(workspace)
            if job.source_kind == "workstation" and (
                request["operation"] == "fix" or request["args"].get("ai_triage")
            ):
                # Explicit opt-in jobs only; never hand platform/database/session
                # credentials to a scanner child.
                for name in (
                    "GEMINI_API_KEY",
                    "GROQ_API_KEY",
                    "GEMINI_PRIMARY_MODEL",
                    "GEMINI_FALLBACK_MODEL",
                    "SILENTSEC_AI_PROVIDERS",
                    "OLLAMA_HOST",
                    "OLLAMA_MODEL",
                    "SILENTSEC_ALLOW_REMOTE_OLLAMA",
                ):
                    if name in os.environ:
                        env[name] = os.environ[name]
                env["SILENTSEC_TRIAGE_CACHE_DIR"] = str(Path(request["cache"]) / "triage")
            command = [
                sys.executable,
                "-m",
                "silentsec.platform.workstation_runner"
                if job.source_kind == "workstation"
                else "silentsec.platform.runner",
                str(request_file),
                str(result_file),
                str(started),
            ]
            options = (
                {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                if os.name == "nt"
                else {"start_new_session": True}
            )
            # Discard tool output: untrusted source and scanner diagnostics must
            # not reach service logs. Safe status codes are stored in the DB.
            process = subprocess.Popen(
                command,
                cwd=workspace,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                **options,
            )
            committed, deadline, failure = (
                False,
                time.monotonic() + limits["scan_timeout"] + 150,
                None,
            )
            try:
                while True:
                    if stop is not None and stop.is_set():
                        failure = "worker_stopping"
                        break
                    if started.exists() and not committed:
                        committed = jobs.mark_started(factory, job_id, token)
                        if not committed:
                            failure = "cancelled"
                            break
                    if process.poll() is not None:
                        break
                    with factory() as db:
                        current = db.get(ScanJob, job_id)
                        if (
                            current.cancel_requested
                            or current.status != "running"
                            or current.worker_token != token
                        ):
                            failure = "cancelled"
                            break
                    if time.monotonic() > deadline:
                        failure = "scan_timeout"
                        break
                    time.sleep(0.2)
            finally:
                if process.poll() is None:
                    _kill_tree(process)
                process.wait(timeout=15)
            if failure or process.returncode != 0 or not result_file.exists():
                safe_code = failure or ("scan_failed" if committed else "source_preparation_failed")
                if not committed and result_file.exists() and result_file.stat().st_size < 512:
                    reported = json.loads(result_file.read_text())
                    if reported.get("error_code") == "scanner_unavailable":
                        safe_code = "scanner_unavailable"
                jobs.finish(
                    factory,
                    job_id,
                    token,
                    error=safe_code,
                )
            elif result_file.stat().st_size <= 12 * 1024 * 1024:
                payload = json.loads(result_file.read_text(encoding="utf-8"))
                jobs.finish(factory, job_id, token, result=payload)
            else:
                jobs.finish(factory, job_id, token, error="result_too_large")
    except (OSError, ValueError, subprocess.SubprocessError):
        jobs.finish(factory, job_id, token, error="worker_error")
    finally:
        if job.source_kind == "upload":
            Path(job.source_reference).unlink(missing_ok=True)
        if job.source_kind == "workstation" and op.input_ref:
            (settings.data_dir.resolve() / "inbox" / (op.input_ref + ".payload")).unlink(
                missing_ok=True
            )


def tick(factory, settings, stop=None):
    jobs.recover(factory)
    item = jobs.claim(factory)
    if item:
        execute(factory, settings, item, stop)
    return item is not None


def loop(factory, settings, stop):
    last_maintenance = 0
    while not stop.is_set():
        if time.monotonic() - last_maintenance >= 60:
            from .__main__ import maintenance

            maintenance(factory, settings)
            last_maintenance = time.monotonic()
        if not tick(factory, settings, stop):
            if settings.redis_url.get_secret_value():
                import redis

                try:
                    with redis.Redis.from_url(
                        settings.redis_url.get_secret_value(), socket_timeout=3
                    ) as client:
                        client.brpop("silentsec:jobs:v1", timeout=1)
                except redis.RedisError:
                    stop.wait(1)
            else:
                stop.wait(1)
