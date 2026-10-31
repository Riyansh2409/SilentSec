"""Versioned loopback-only API and static frontend server, using the stdlib."""

from __future__ import annotations

import argparse
import concurrent.futures
import hmac
import json
import mimetypes
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .config import resolve_backend

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    "scan",
    "history",
    "verify",
    "fix",
    "report",
    "github",
    "upload",
    "gate",
    "verify_github",
    "verify_upload",
}
MAX_BODY = 29_000_000


class InputError(ValueError):
    pass


def clean_path(value: str) -> str:
    """Strip whitespace and one pair of matching quotes ("Copy as path" on Windows)."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1].strip()
    return value


def validate_request(body: dict) -> tuple[str, dict]:
    if not isinstance(body, dict) or body.get("operation") not in OPERATIONS:
        raise InputError("Choose a supported operation.")
    op = body["operation"]
    args = body.get("args")
    if not isinstance(args, dict):
        raise InputError("Operation settings must be an object.")
    if op in {"github", "upload", "verify_github", "verify_upload"}:
        args = args.copy()
        if op in {"github", "verify_github"}:
            import re

            if set(args) - (
                {"url", "commits", "timeout"}
                if op == "github"
                else {"url", "patch", "targets", "timeout"}
            ):
                raise InputError("Unknown GitHub scan setting.")
            if not isinstance(args.get("url"), str) or not re.fullmatch(
                r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/?", args["url"].strip()
            ):
                raise InputError("Enter a public https://github.com/owner/repository link.")
            for key, low, high in (("commits", 0, 20), ("timeout", 10, 900)):
                if key in args and (type(args[key]) is not int or not low <= args[key] <= high):
                    raise InputError(f"{key} must be between {low} and {high}.")
        else:
            import base64

            if (
                set(args)
                != (
                    {"filename", "content", "patch"}
                    if op == "verify_upload"
                    else {"filename", "content"}
                )
                or not isinstance(args["filename"], str)
                or len(args["filename"]) > 200
            ):
                raise InputError("Choose one ZIP or source file.")
            try:
                data = base64.b64decode(args["content"], validate=True)
            except (ValueError, TypeError):
                raise InputError("Invalid upload content.") from None
            if not 0 < len(data) <= 20 * 1024 * 1024:
                raise InputError("Choose a nonempty file up to 20 MB.")
        if op.startswith("verify_"):
            if (
                not isinstance(args.get("patch"), str)
                or not args["patch"].strip()
                or len(args["patch"].encode()) > 1_000_000
            ):
                raise InputError("Choose a nonempty patch smaller than 1 MB.")
            targets = args.get("targets")
            if targets is not None and (
                not isinstance(targets, list)
                or len(targets) > 100
                or any(not isinstance(x, str) or len(x) > 500 for x in targets)
            ):
                raise InputError("Invalid target fingerprints.")
        return op, args
    allowed = {
        "repo_path",
        "timeout",
        "ai_triage",
        "max_ai_findings",
        "use_cache",
        "commits",
        "run_tests",
        "strict",
        "patch",
        "targets",
        "fingerprint",
        "include_history",
        "fix_job_ids",
        "base",
        "head",
        "fail_on",
        "fail_on_architecture",
        "include_tests",
    }
    if set(args) - allowed:
        raise InputError("Unknown operation setting.")
    args = args.copy()
    if op == "gate":
        for key in ("base", "head"):
            value = args.get(key, "main" if key == "base" else "HEAD")
            if (
                not isinstance(value, str)
                or not value.strip()
                or len(value) > 200
                or value.strip().startswith("-")
                or "\x00" in value
            ):
                raise InputError(f"Invalid {key} revision.")
            args[key] = value.strip()
        if args.get("fail_on", "high") not in {"critical", "high", "medium", "low", "info"}:
            raise InputError("Invalid gate severity threshold.")
    path = args.get("repo_path")
    if not isinstance(path, str) or len(path) > 4096 or not clean_path(path):
        raise InputError("Enter a local repository folder path.")
    path = clean_path(path)
    if path.startswith(("\\\\", "//")) or "://" in path:
        raise InputError("Use a folder on this computer, not a URL or network share.")
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise InputError("The repository folder does not exist on this computer.")
    args["repo_path"] = str(root)
    for key, lo, hi in (("timeout", 1, 600), ("commits", 1, 50), ("max_ai_findings", 1, 100)):
        if key in args and (type(args[key]) is not int or not lo <= args[key] <= hi):
            raise InputError(f"{key} must be a whole number from {lo} to {hi}.")
    for key in (
        "ai_triage",
        "use_cache",
        "run_tests",
        "strict",
        "include_history",
        "fail_on_architecture",
        "include_tests",
    ):
        if key in args and type(args[key]) is not bool:
            raise InputError(f"{key} must be true or false.")
    for key in ("targets", "fix_job_ids"):
        if key in args and (
            not isinstance(args[key], list)
            or len(args[key]) > 100
            or any(not isinstance(x, str) or len(x) > 500 for x in args[key])
        ):
            raise InputError(f"Invalid {key}.")
    if "fingerprint" in args and (
        not isinstance(args["fingerprint"], str) or len(args["fingerprint"]) > 500
    ):
        raise InputError("Invalid finding identity.")
    if op == "verify" and (
        not isinstance(args.get("patch"), str)
        or not args["patch"].strip()
        or len(args["patch"].encode("utf-8")) > 200_000
    ):
        raise InputError("Choose a text patch smaller than 200 KB.")
    return op, args


class State:
    def __init__(self, backend: Path, data_root: Path):
        self.backend, self.data_root = backend, data_root
        data_root.mkdir(parents=True, exist_ok=True)
        self.token = secrets.token_urlsafe(32)
        self.jobs = {}
        self.lock = threading.Lock()
        self.children = set()
        self.stopping = threading.Event()
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.health = self.invoke("probe", {}, data_root / "probe", timeout=45)

    def invoke(self, operation, args, folder, timeout):
        folder.mkdir(parents=True, exist_ok=True)
        request, result = folder / "request.json", folder / "result.json"
        result.unlink(missing_ok=True)
        request.write_text(
            json.dumps(
                {
                    "operation": operation,
                    "args": args,
                    "backend_path": str(self.backend),
                    "data_root": str(self.data_root),
                }
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["PATH"] = (
            str(ROOT / ".tools")
            + os.pathsep
            + str(Path(sys.executable).parent)
            + os.pathsep
            + env.get("PATH", "")
        )
        if operation != "probe" and operation != "fix" and not args.get("ai_triage"):
            for key in ("GEMINI_API_KEY", "GROQ_API_KEY", "GOOGLE_API_KEY"):
                env.pop(key, None)
        try:
            with (folder / "worker.log").open("wb") as log:
                child = subprocess.Popen(
                    [sys.executable, "-m", "local_api.worker", str(request), str(result)],
                    cwd=ROOT,
                    env=env,
                    stdout=log,
                    stderr=log,
                    shell=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    start_new_session=os.name != "nt",
                )
                with self.lock:
                    self.children.add(child)
                try:
                    child.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                    else:
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                    return {
                        "ok": False,
                        "error": "The operation exceeded its time limit. No result was confirmed.",
                    }
                finally:
                    with self.lock:
                        self.children.discard(child)
            if result.is_file():
                return json.loads(result.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        return {
            "ok": False,
            "error": "The backend worker could not finish. Check the local worker log and setup.",
        }

    def start(self, op, args):
        with self.lock:
            if self.stopping.is_set():
                raise InputError("The local service is stopping.")
            if any(j["status"] in {"queued", "running"} for j in self.jobs.values()):
                raise InputError("Another operation is running. Wait for it to finish.")
            if len(self.jobs) >= 100:
                raise InputError(
                    "This session has reached 100 operations. Restart the local server for a new session."
                )
            if op == "report":
                paths = []
                for id_ in args.pop("fix_job_ids", []):
                    job = self.jobs.get(id_)
                    if (
                        not job
                        or job["operation"] not in {"fix", "verify"}
                        or job["status"] != "succeeded"
                    ):
                        raise InputError(
                            "Choose a completed fix or verification from this session."
                        )
                    if job["repo_path"] != args["repo_path"]:
                        raise InputError("Fix reports must belong to the same repository.")
                    paths.append(str(self.data_root / id_ / "export.json"))
                args["fix_paths"] = paths
            id_ = uuid.uuid4().hex
            job = {
                "id": id_,
                "operation": op,
                "repo_path": args.get(
                    "repo_path", args.get("url", args.get("filename", "Source scan"))
                ),
                "status": "queued",
                "started_at": time.time(),
                "finished_at": None,
                "error": None,
            }
            self.jobs[id_] = job
        self.pool.submit(self.execute, id_, op, args)
        return dict(job)

    def execute(self, id_, op, args):
        with self.lock:
            self.jobs[id_]["status"] = "running"
        factor = args.get("commits", 10) if op in {"history", "report"} else 1
        timeout = min(
            86400,
            (args.get("timeout", 180) * 4 + 90) * factor * (3 if op in {"verify", "fix"} else 1)
            + 600,
        )
        result = self.invoke(op, args, self.data_root / id_, timeout)
        if result["ok"]:
            (self.data_root / id_ / "export.json").write_text(
                json.dumps(result["data"], indent=2), encoding="utf-8"
            )
        with self.lock:
            self.jobs[id_].update(
                status="succeeded" if result["ok"] else "failed",
                finished_at=time.time(),
                error=result.get("error"),
            )

    def close(self):
        self.stopping.set()
        with self.lock:
            children = list(self.children)
        for child in children:
            if child.poll() is None:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                else:
                    os.killpg(child.pid, signal.SIGKILL)
        self.pool.shutdown(wait=True, cancel_futures=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "SilentSecLocal/1"

    def log_message(self, *_):
        pass  # Avoid writing user paths and finding data to terminal logs.

    @property
    def state(self):
        return self.server.state

    def send(self, status, payload, content_type="application/json; charset=utf-8", download=None):
        data = json.dumps(payload).encode() if isinstance(payload, (dict, list)) else payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(data)

    def allowed(self, token=True):
        hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        if host not in hosts or (origin and origin != f"http://{host}"):
            self.send(403, {"error": "This server accepts same-origin local requests only."})
            return False
        if token and not hmac.compare_digest(
            self.headers.get("X-SilentSec-Token", ""), self.state.token
        ):
            self.send(403, {"error": "Refresh the local page to reconnect."})
            return False
        return True

    def do_GET(self):
        path = urlparse(self.path).path
        if not self.allowed(token=path.startswith("/api/") and path != "/api/v1/health"):
            return
        if path == "/api/v1/health":
            health = self.state.health
            self.send(
                200,
                {
                    "api_version": "1",
                    "local_only": True,
                    "token": self.state.token,
                    "backend_ready": health["ok"],
                    "backend": health.get("data"),
                    "error": health.get("error"),
                },
            )
        elif path == "/api/v1/jobs":
            with self.state.lock:
                self.send(
                    200, {"jobs": [dict(j) for j in reversed(list(self.state.jobs.values()))]}
                )
        elif path.startswith("/api/v1/jobs/"):
            parts = path.split("/")
            if (
                len(parts) not in {5, 6}
                or not parts[4]
                or (len(parts) == 6 and parts[5] not in {"result", "report", "sarif"})
            ):
                self.send(404, {"error": "Unknown job route."})
                return
            id_ = parts[4]
            with self.state.lock:
                job = dict(self.state.jobs[id_]) if id_ in self.state.jobs else None
            if not job:
                self.send(404, {"error": "Operation not found in this server session."})
                return
            if len(parts) == 5:
                self.send(200, job)
            elif job["status"] != "succeeded":
                self.send(409, {"error": "The operation has no completed result."})
            elif parts[5] == "sarif" and job["operation"] in {"scan", "gate"}:
                artifact = self.state.data_root / id_ / "silentsec.sarif"
                if not artifact.is_file():
                    self.send(404, {"error": "SARIF is unavailable for this operation."})
                    return
                self.send(200, artifact.read_bytes(), "application/sarif+json", "silentsec.sarif")
            elif parts[5] == "result":
                self.send(200, (self.state.data_root / id_ / "export.json").read_bytes())
            elif parts[5] == "report" and job["operation"] in {"report", "github", "upload"}:
                self.send(
                    200,
                    (self.state.data_root / id_ / "report.html").read_bytes(),
                    "text/html; charset=utf-8",
                    "silentsec-report.html",
                )
            else:
                self.send(404, {"error": "Unknown result type."})
        elif path.startswith("/api/"):
            self.send(404, {"error": "Unknown API route."})
        else:
            # Explicit static files prevent source, credentials and data-directory exposure.
            files = {
                "/": "index.html",
                "/index.html": "index.html",
                "/app": "app.html",
                "/app.html": "app.html",
                "/app.css": "app.css",
                "/app.js": "app.js",
                "/api.js": "api.js",
                "/data.js": "data.js",
                "/debt-views.js": "debt-views.js",
            }
            filename = files.get(path)
            if not filename or not (ROOT / "web" / filename).is_file():
                self.send(404, {"error": "Page not found."})
                return
            self.send(
                200,
                (ROOT / "web" / filename).read_bytes(),
                (mimetypes.guess_type(filename)[0] or "text/plain") + "; charset=utf-8",
            )

    def do_POST(self):
        if not self.allowed():
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BODY:
                raise InputError("Request is empty or too large.")
            if self.headers.get_content_type() != "application/json":
                raise InputError("Use JSON request data.")
            body = json.loads(self.rfile.read(size))
            if self.path == "/api/v1/jobs":
                op, args = validate_request(body)
                if not self.state.health["ok"]:
                    raise InputError("Backend setup is incomplete. Run setup.ps1 and restart.")
                if not self.state.health["data"]["capabilities"].get(op):
                    raise InputError(
                        "This backend version needs an adapter update for this operation."
                    )
                if (op == "fix" or args.get("ai_triage")) and not self.state.health["data"][
                    "ai_configured"
                ]:
                    raise InputError(
                        self.state.health["data"].get("ai_configuration_error")
                        or "No AI provider is configured. Configure Ollama or cloud credentials in the server environment, then restart. Scanning works without AI."
                    )
                self.send(202, self.state.start(op, args))
            elif self.path == "/api/v1/context":
                if not isinstance(body, dict):
                    raise InputError("Invalid finding request.")
                job = self.state.jobs.get(body.get("job_id"))
                if not job or job["operation"] != "scan" or job["status"] != "succeeded":
                    raise InputError("Choose a finding from a completed scan.")
                data = json.loads(
                    (self.state.data_root / job["id"] / "export.json").read_text(encoding="utf-8")
                )
                candidates = [*data["findings"], *(data.get("test_findings") or [])]
                finding = next(
                    (f for f in candidates if f["fingerprint"] == body.get("fingerprint")),
                    None,
                )
                if not finding:
                    raise InputError("Finding not present in this scan.")
                result = self.state.invoke(
                    "context",
                    {
                        "repo_path": job["repo_path"],
                        "finding": finding,
                        # Lines flagged as secrets are withheld from the snippet.
                        "secret_findings": [
                            f
                            for f in candidates
                            if f.get("category") == "secret"
                            and f.get("file_path") == finding.get("file_path")
                        ],
                    },
                    self.state.data_root / "context" / uuid.uuid4().hex,
                    30,
                )
                self.send(
                    200 if result["ok"] else 400,
                    result.get("data") or {"error": result.get("error")},
                )
            else:
                self.send(404, {"error": "Unknown API route."})
        except (ValueError, TypeError, KeyError, OSError) as exc:
            message = (
                str(exc)
                if isinstance(exc, InputError)
                else "The request could not be read. Check its fields and try again."
            )
            self.send(400, {"error": message})


def load_backend_env(backend: Path) -> None:
    """Load the backend checkout's .env (names only, never values; existing vars win)."""
    source = str(backend / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    try:
        from silentsec.envfile import ENV_FILE_VARIABLE, load_env_file
    except ImportError:
        return
    explicit = os.environ.get(ENV_FILE_VARIABLE, "").strip()
    names = load_env_file(Path(explicit).expanduser() if explicit else backend / ".env")
    if names:
        print(f"Loaded {len(names)} setting(s) from .env: {', '.join(sorted(names))}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Run the SilentSec local frontend and API.")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--backend", type=Path, default=None)
    args = parser.parse_args()
    config_path = ROOT / ".data" / "config.json"
    config_path.parent.mkdir(exist_ok=True)
    config = (
        json.loads(config_path.read_text(encoding="utf-8-sig")) if config_path.is_file() else {}
    )
    try:
        backend = resolve_backend(ROOT, args.backend)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    config["backend_path"] = str(backend.resolve())
    load_backend_env(backend.resolve())
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.state = State(backend.resolve(), ROOT / ".data")
    print(f"SilentSec local: http://127.0.0.1:{args.port}", flush=True)
    print(
        "Press Ctrl+C to stop. Optional AI follows the configured local/external provider order.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.state.close()


if __name__ == "__main__":
    main()
