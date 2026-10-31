import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from local_api.adapter import provider_configuration
from local_api.config import resolve_backend


def provider_env(extra):
    environment = os.environ.copy()
    for key in (
        "SILENTSEC_AI_PROVIDERS",
        "GEMINI_API_KEY",
        "GROQ_API_KEY",
        "GEMINI_PRIMARY_MODEL",
        "GEMINI_FALLBACK_MODEL",
        "OLLAMA_HOST",
        "OLLAMA_MODEL",
        "OLLAMA_TIMEOUT",
        "SILENTSEC_OLLAMA_ALLOW_REMOTE",
    ):
        environment.pop(key, None)
    environment.update(extra)
    return patch.dict(os.environ, environment, clear=True)


class ProviderConfigurationTests(unittest.TestCase):
    def test_ollama_without_cloud_key_does_not_make_requests(self):
        with (
            provider_env({"SILENTSEC_AI_PROVIDERS": "ollama"}),
            patch(
                "httpx.Client.send", side_effect=AssertionError("Probe must not contact a model")
            ),
        ):
            status = provider_configuration()
        self.assertTrue(status["ai_configured"])
        self.assertTrue(status["ai_local_only"])
        self.assertEqual(status["ai_providers"][0]["name"], "ollama")

    def test_local_ollama_and_cloud_fallback_are_disclosed(self):
        local = SimpleNamespace(
            model="local-model", _client=SimpleNamespace(host="http://localhost:11434")
        )
        cloud = SimpleNamespace(model="cloud-model")
        with patch(
            "silentsec.triage.factory.build_default_providers",
            return_value=[("ollama", local), ("groq", cloud)],
        ):
            status = provider_configuration()
        self.assertTrue(status["ai_configured"])
        self.assertFalse(status["ai_local_only"])
        self.assertEqual([p["scope"] for p in status["ai_providers"]], ["local", "external"])

    def test_remote_ollama_is_not_mislabeled_local(self):
        env = {
            "SILENTSEC_AI_PROVIDERS": "ollama",
            "OLLAMA_HOST": "http://192.0.2.1:11434",
            "SILENTSEC_OLLAMA_ALLOW_REMOTE": "1",
        }
        with (
            provider_env(env),
            patch("httpx.Client.send", side_effect=AssertionError("No model request")),
        ):
            status = provider_configuration()
        self.assertTrue(status["ai_configured"])
        self.assertFalse(status["ai_local_only"])

    def test_invalid_provider_configuration_does_not_break_basic_scans(self):
        for env in (
            {"SILENTSEC_AI_PROVIDERS": "unknown"},
            {"SILENTSEC_AI_PROVIDERS": "ollama", "OLLAMA_HOST": "http://192.0.2.1:11434"},
        ):
            with self.subTest(env=env), provider_env(env):
                status = provider_configuration()
                self.assertFalse(status["ai_configured"])
                self.assertTrue(status["ai_configuration_error"])

    def test_no_provider_is_not_reported_as_configured(self):
        with provider_env({}):
            self.assertFalse(provider_configuration()["ai_configured"])


class BackendLocationTests(unittest.TestCase):
    def test_sibling_backend_is_the_default(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            frontend = root / "frontend"
            frontend.mkdir()
            file = root / "src/silentsec/scanners/scanner_service.py"
            file.parent.mkdir(parents=True)
            file.write_text("")
            self.assertEqual(resolve_backend(frontend), root.resolve())

    def test_explicit_backend_overrides_saved_config(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            frontend = root / "frontend"
            (frontend / ".data").mkdir(parents=True)
            (frontend / ".data/config.json").write_text('{"backend_path":"missing-folder"}')
            file = root / "src/silentsec/scanners/scanner_service.py"
            file.parent.mkdir(parents=True)
            file.write_text("")
            self.assertEqual(resolve_backend(frontend, root), root.resolve())
