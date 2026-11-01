import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from local_api.server import Handler, InputError, State, validate_request


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_scan_defaults_do_not_enable_ai_or_tests(self):
        operation, args = validate_request({"operation": "scan", "args": {"repo_path": self.path}})
        self.assertEqual(operation, "scan")
        self.assertFalse(args.get("ai_triage", False))
        self.assertFalse(args.get("run_tests", False))

    def test_reject_command_injection_fields_and_bad_types(self):
        for extras in (
            {"test_command": "anything"},
            {"timeout": True},
            {"run_tests": "false"},
            {"commits": 51},
            {"max_ai_findings": 0},
        ):
            with self.subTest(extras=extras), self.assertRaises(InputError):
                validate_request({"operation": "scan", "args": {"repo_path": self.path, **extras}})

    def test_quoted_windows_paths_are_accepted(self):
        expected = str(Path(self.path).resolve())
        for raw in (f'"{self.path}"', f"'{self.path}'", f'  "{self.path}"  ', f" {self.path} "):
            with self.subTest(raw=raw):
                _, args = validate_request({"operation": "scan", "args": {"repo_path": raw}})
                self.assertEqual(args["repo_path"], expected)

    def test_unbalanced_or_empty_quotes_are_rejected(self):
        for raw in (f'"{self.path}', '""', "''", '"  "'):
            with self.subTest(raw=raw), self.assertRaises(InputError):
                validate_request({"operation": "scan", "args": {"repo_path": raw}})

    def test_quoted_network_paths_are_still_rejected(self):
        for raw in ('"\\\\server\\share"', "'//server/share'", '"https://example.com/x"'):
            with self.subTest(raw=raw), self.assertRaises(InputError):
                validate_request({"operation": "scan", "args": {"repo_path": raw}})

    def test_network_paths_are_not_local_inputs(self):
        for path in ("https://github.com/example/repo", "\\\\server\\share", "//server/share"):
            with self.assertRaises(InputError):
                validate_request({"operation": "scan", "args": {"repo_path": path}})

    def test_patch_limits(self):
        for value in ("", "x" * 200001, None):
            with self.assertRaises(InputError):
                validate_request(
                    {"operation": "verify", "args": {"repo_path": self.path, "patch": value}}
                )

    def test_report_cannot_mix_repositories(self):
        state = object.__new__(State)
        state.lock = threading.Lock()
        state.stopping = threading.Event()
        state.jobs = {
            "fix1": {
                "id": "fix1",
                "operation": "fix",
                "status": "succeeded",
                "repo_path": "another-repository",
            }
        }
        state.data_root = Path(self.path)
        with self.assertRaisesRegex(InputError, "same repository"):
            state.start("report", {"repo_path": self.path, "fix_job_ids": ["fix1"]})


class HTTPBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.state = SimpleNamespace(
            token="local-test-token",
            health={
                "ok": True,
                "data": {"capabilities": {"scan": True, "fix": True}, "ai_configured": False},
            },
            jobs={},
            lock=threading.Lock(),
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, headers=None, method="GET", body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        result = conn.getresponse()
        payload = result.read()
        conn.close()
        return result.status, payload

    def test_health_then_authenticated_jobs(self):
        code, payload = self.request("/api/v1/health")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(payload)["api_version"], "1")
        self.assertEqual(self.request("/api/v1/jobs")[0], 403)
        self.assertEqual(
            self.request("/api/v1/jobs", {"X-SilentSec-Token": "local-test-token"})[0], 200
        )

    def test_foreign_origin_and_host_rejected(self):
        self.assertEqual(
            self.request("/api/v1/health", {"Origin": "https://unrelated.example"})[0], 403
        )
        self.assertEqual(self.request("/api/v1/health", {"Host": "unrelated.example"})[0], 403)

    def test_static_allowlist_does_not_expose_source_or_results(self):
        for path in (
            "/../local_api/server.py",
            "/.data/probe/result.json",
            "/backend/.env.example",
        ):
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request("/app")[0], 200)

    def test_ai_operation_requires_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            code, body = self.request(
                "/api/v1/jobs",
                {"X-SilentSec-Token": "local-test-token", "Content-Type": "application/json"},
                "POST",
                json.dumps({"operation": "fix", "args": {"repo_path": folder}}),
            )
        self.assertEqual(code, 400)
        self.assertIn("No AI provider", json.loads(body)["error"])


class AdapterTests(unittest.TestCase):
    def test_scan_keeps_backend_score_and_explicit_options(self):
        from local_api import adapter

        sample = {"security_debt": {"score": 73.125}, "security_debt_complete": False}
        calls = []

        def scan(path, **kwargs):
            calls.append((path, kwargs))
            return SimpleNamespace(model_dump=lambda **_: sample)

        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(adapter, "interfaces", return_value={"scan": scan}),
            patch("silentsec.report.sarif.scan_to_sarif", return_value={"version": "2.1.0"}),
        ):
            actual = adapter.run("scan", {"repo_path": folder}, Path(folder), Path(folder))
        self.assertEqual(actual, sample)
        self.assertFalse(calls[0][1]["enable_ai_triage"])
        self.assertEqual(calls[0][1]["max_ai_triage_findings"], 20)

    def test_current_backend_contract(self):
        from local_api.adapter import probe

        result = probe()
        self.assertTrue(all(result["capabilities"].values()), result)


if __name__ == "__main__":
    unittest.main()
