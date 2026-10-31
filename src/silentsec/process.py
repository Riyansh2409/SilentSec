"""Run external tools with a timeout that really stops them.

``subprocess.run(timeout=...)`` only kills the process it started. Scanners
such as Semgrep start helper processes (``semgrep-core``) that keep running,
and keep the output pipes open, so the call returns minutes late and leaves
orphan processes behind; on Windows a "180 second" timeout took 212-243s.

``run_bounded`` starts the tool in its own process group and, on timeout,
kills the whole tree: ``taskkill /T /F`` on Windows, ``killpg`` elsewhere.
"""

import os
import signal
import subprocess  # nosec B404
from collections.abc import Mapping, Sequence
from pathlib import Path

# After killing the tree, how long to wait for the pipes to close.
KILL_GRACE_SECONDS = 5
TASKKILL_TIMEOUT_SECONDS = 10


def _kill_tree(process: subprocess.Popen) -> None:
    if os.name == "nt":
        try:
            # A fixed argument list without a shell; the PID is an integer.
            subprocess.run(  # nosec B603 B607
                ["taskkill", "/T", "/F", "/PID", str(process.pid)],
                capture_output=True,
                timeout=TASKKILL_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            # The process was started in a new session, so its group id is its pid.
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def run_bounded(
    command: Sequence[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Like ``subprocess.run(..., capture_output=True, text=True)`` without a shell.

    Raises ``subprocess.TimeoutExpired`` after killing the whole process tree,
    and ``FileNotFoundError``/``OSError`` when the program cannot start.
    """
    options: dict = {}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True

    # Callers pass fixed argument lists; shell execution is disabled.
    process = subprocess.Popen(  # nosec B603
        list(command),
        cwd=cwd,
        env=dict(env) if env is not None else None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        **options,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        try:
            process.communicate(timeout=KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        raise subprocess.TimeoutExpired(list(command), timeout) from None
    except BaseException:  # e.g. Ctrl+C: do not leave the tool running
        _kill_tree(process)
        raise
    return subprocess.CompletedProcess(list(command), process.returncode, stdout, stderr)
