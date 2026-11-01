import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from local_api.server import InputError, validate_request
from test_local_api import HTTPBoundaryTests


class GateValidationTests(unittest.TestCase):
    def test_gate_revisions_and_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            base = {"operation": "gate", "args": {"repo_path": folder}}
            _, args = validate_request(base)
            self.assertEqual((args["base"], args["head"]), ("main", "HEAD"))
            _, args = validate_request(
                {"operation": "gate", "args": {"repo_path": folder, "include_tests": True}}
            )
            self.assertTrue(args["include_tests"])
            for bad in (
                {"head": "--help"},
                {"base": "x" * 201},
                {"head": ""},
                {"head": 3},
                {"base": " -bad"},
                {"fail_on": "severe"},
                {"fail_on_architecture": "false"},
                {"include_tests": "yes"},
            ):
                with self.subTest(bad=bad), self.assertRaises(InputError):
                    validate_request({"operation": "gate", "args": {"repo_path": folder, **bad}})

    def test_native_verification_rejects_tests_and_bad_targets(self):
        args = {
            "url": "https://github.com/example/repo",
            "patch": "a patch",
            "targets": ["fingerprint"],
        }
        self.assertEqual(
            validate_request({"operation": "verify_github", "args": args})[0], "verify_github"
        )
        for extra in ({"run_tests": True}, {"targets": [7]}, {"patch": ""}):
            with self.assertRaises(InputError):
                validate_request({"operation": "verify_github", "args": {**args, **extra}})


class ArtifactRoutesTests(HTTPBoundaryTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.temp = tempfile.TemporaryDirectory()
        cls.server.state.data_root = Path(cls.temp.name)
        folder = Path(cls.temp.name) / "example"
        folder.mkdir()
        (folder / "silentsec.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
        cls.server.state.jobs["example"] = {
            "id": "example",
            "status": "succeeded",
            "operation": "gate",
        }

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.temp.cleanup()

    def test_sarif_and_malformed_paths(self):
        headers = {"X-SilentSec-Token": "local-test-token"}
        code, data = self.request("/api/v1/jobs/example/sarif", headers)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(data)["version"], "2.1.0")
        self.assertEqual(self.request("/api/v1/jobs/example/sarif")[0], 403)
        for path in [
            "/api/v1/jobs/",
            "/api/v1/jobs/example/",
            "/api/v1/jobs/example/result/extra",
            "/api/v1/jobs/example/unknown",
        ]:
            self.assertEqual(self.request(path, headers)[0], 404)


class ViewDataTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node needed for view-data checks")
    def test_reintroduction_merges_tags_and_optional_scanner(self):
        check = Path(__file__).with_name("view-data.mjs")
        subprocess.run(["node", str(check)], check=True, capture_output=True, text=True)
