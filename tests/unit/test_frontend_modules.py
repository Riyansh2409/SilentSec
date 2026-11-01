"""Browser scripts load as ES modules; check them the same way.

`node --check app.js` parses a .js file as CommonJS, whose wrapper adds a
closing brace and hid a missing `}` in app.js. Copying to .mjs makes Node
parse it as a module, exactly like the browser's <script type="module">.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = sorted((ROOT / "frontend" / "web").glob("*.js")) + sorted(
    (ROOT / "frontend" / "platform").glob("*.js")
)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: f"{path.parent.name}/{path.name}")
def test_browser_script_parses_as_es_module(script: Path, tmp_path: Path):
    module = tmp_path / (script.stem + ".mjs")
    module.write_bytes(script.read_bytes())
    result = subprocess.run(
        ["node", "--check", str(module)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_every_web_import_is_served_by_the_platform():
    """Each ./x.js the workspace imports must be in the platform's asset allowlist."""
    import re

    app_source = (ROOT / "src" / "silentsec" / "platform" / "app.py").read_text(encoding="utf-8")
    imported = set()
    for script in (ROOT / "frontend" / "web").glob("*.js"):
        imported |= set(re.findall(r"from\s+'\./([\w-]+\.js)'", script.read_text(encoding="utf-8")))
        imported |= set(re.findall(r"import\('\./([\w-]+\.js)'\)", script.read_text(encoding="utf-8")))
    assert imported, "expected app.js to import local modules"
    for name in sorted(imported):
        assert f'"{name}"' in app_source, f"{name} is imported by the workspace but not served"
