from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    yaml.safe_load((ROOT / "project.platform.yaml").read_text(encoding="utf-8")).get("template_mode"),
    "bootstrap utility tests apply to the pristine template, not an adopted legacy-migration repository",
)
class BootstrapProfilesTests(unittest.TestCase):
    def _copy_template(self, temporary: str) -> Path:
        target = Path(temporary) / "project"
        shutil.copytree(
            ROOT,
            target,
            ignore=shutil.ignore_patterns("__pycache__", ".git", "artifacts", ".template-bootstrap.json"),
        )
        return target

    def test_tool_bootstrap_records_coolify_route_and_reusable_container_port(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = self._copy_template(temporary)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(target / "scripts/bootstrap.py"),
                    "--project-name", "Example Tool",
                    "--project-slug", "example-tool",
                    "--description", "An internal example tool used to validate template bootstrap.",
                    "--owner-team", "platform-team",
                    "--technical-owner", "technical-owner",
                    "--product-owner", "product-owner",
                    "--project-kind", "tool",
                    "--base-url", "https://example-tool.example.com",
                    "--container-port", "3000",
                    "--coolify-server", "main-server",
                    "--coolify-project", "internal-tools",
                ],
                cwd=target,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            manifest = yaml.safe_load((target / "project.platform.yaml").read_text(encoding="utf-8"))
            registration = yaml.safe_load((target / "deployment.registration.yaml").read_text(encoding="utf-8"))
            self.assertEqual("tool", manifest["project"]["kind"])
            self.assertEqual("coolify", manifest["deployment"]["platform"])
            self.assertEqual("example-tool.example.com", manifest["deployment"]["public_routes"][0]["hostname"])
            self.assertEqual(3000, manifest["deployment"]["services"][0]["container_port"])
            self.assertTrue(manifest["deployment"]["port_policy"]["container_ports_may_repeat_across_coolify_resources"])
            self.assertEqual([], registration["published_host_ports"])

    def test_sdk_bootstrap_has_no_coolify_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = self._copy_template(temporary)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(target / "scripts/bootstrap.py"),
                    "--project-name", "UNGUESS Example SDK",
                    "--project-slug", "unguess-example-sdk",
                    "--description", "A versioned reusable package with no independently deployed runtime.",
                    "--owner-team", "platform-team",
                    "--technical-owner", "technical-owner",
                    "--product-owner", "product-owner",
                    "--project-kind", "sdk_library",
                ],
                cwd=target,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            manifest = yaml.safe_load((target / "project.platform.yaml").read_text(encoding="utf-8"))
            registration = yaml.safe_load((target / "deployment.registration.yaml").read_text(encoding="utf-8"))
            self.assertEqual("sdk_library", manifest["project"]["kind"])
            self.assertFalse(manifest["deployment"]["applicable"])
            self.assertEqual("none", manifest["deployment"]["platform"])
            self.assertEqual([], manifest["deployment"]["services"])
            self.assertEqual([], manifest["deployment"]["public_routes"])
            self.assertEqual("exempt", registration["registry"]["status"])


if __name__ == "__main__":
    unittest.main()
