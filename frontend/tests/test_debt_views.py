import shutil
import subprocess
import unittest
from pathlib import Path


class DebtViewTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required for rendering unit test')
    def test_safe_rendering_and_module_navigation(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ['node', str(root / 'tests' / 'debt_views_test.cjs')],
            cwd=root, capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
