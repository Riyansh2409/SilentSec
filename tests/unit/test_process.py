import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from silentsec.process import KILL_GRACE_SECONDS, run_bounded

# A child that starts a grandchild sleeping for a minute, writes the
# grandchild's PID to a file, and then sleeps itself. This is what Semgrep
# does with semgrep-core: killing only the child leaves the grandchild alive.
SPAWNER = """
import subprocess, sys, time
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open(sys.argv[1], "w") as handle:
    handle.write(str(grandchild.pid))
time.sleep(60)
"""


def _alive(pid: int) -> bool:
    if os.name == "nt":
        listing = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, check=False
        ).stdout
        return str(pid) in listing
    status = Path(f"/proc/{pid}/status")
    if status.exists():  # Linux: a killed but not yet reaped process is a zombie
        return "\nState:\tZ" not in status.read_text()
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_output_and_exit_code_are_returned(tmp_path: Path):
    completed = run_bounded(
        [
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)",
        ],
        cwd=tmp_path,
        timeout=30,
    )

    assert completed.returncode == 3
    assert completed.stdout.strip() == "out"
    assert completed.stderr.strip() == "err"


def test_environment_is_passed(tmp_path: Path):
    env = {**os.environ, "SILENTSEC_TEST_VALUE": "hello"}
    completed = run_bounded(
        [sys.executable, "-c", "import os; print(os.environ['SILENTSEC_TEST_VALUE'])"],
        timeout=30,
        env=env,
    )

    assert completed.stdout.strip() == "hello"


def test_missing_program_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        run_bounded(["silentsec-no-such-program-xyz"], timeout=5)


def test_timeout_kills_the_whole_process_tree(tmp_path: Path):
    pid_file = tmp_path / "grandchild.pid"
    script = tmp_path / "spawner.py"
    script.write_text(SPAWNER, encoding="utf-8")

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded([sys.executable, str(script), str(pid_file)], timeout=3)
    elapsed = time.monotonic() - started

    assert elapsed < 3 + KILL_GRACE_SECONDS + 2
    grandchild = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while _alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not _alive(grandchild), "the grandchild process survived the timeout"
