from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("platform_check", ROOT / "scripts/platform_check.py")
assert SPEC and SPEC.loader
platform_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = platform_check
SPEC.loader.exec_module(platform_check)


class DeploymentRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.local = yaml.safe_load((ROOT / "deployment.registration.yaml").read_text(encoding="utf-8"))

    def _new_entry(self, suffix: str) -> dict:
        entry = copy.deepcopy(self.local)
        entry["registration_id"] = f"example-{suffix}:production"
        entry["project_slug"] = f"example-{suffix}"
        entry["coolify"]["resource_name"] = f"example-{suffix}-production"
        if entry["routes"]:
            entry["routes"][0]["hostname"] = f"example-{suffix}.example.invalid"
        return entry

    def _check(self, entries: list[dict]) -> platform_check.CheckResult:
        registry = {
            "schema_version": 1,
            "registry_name": "unguess-coolify-deployments",
            "updated_at": "2026-08-18T12:00:00Z",
            "deployments": entries,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deployments.yml"
            path.write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
            result = platform_check.CheckResult()
            platform_check.check_central_deployment_registry(ROOT, self.local, path, result)
            return result

    def test_container_port_can_be_reused_by_another_coolify_resource(self) -> None:
        second = self._new_entry("same-container-port")
        self.assertEqual(
            self.local["services"][0]["container_port"],
            second["services"][0]["container_port"],
        )
        report = self._check([self.local, second])
        self.assertEqual([], report.errors, "\n".join(report.errors))

    def test_duplicate_hostname_and_path_are_rejected(self) -> None:
        second = self._new_entry("duplicate-route")
        second["routes"][0]["hostname"] = self.local["routes"][0]["hostname"]
        second["routes"][0]["path"] = self.local["routes"][0]["path"]
        report = self._check([self.local, second])
        self.assertTrue(any("Duplicate deployment route" in error for error in report.errors))

    def test_wildcard_and_specific_host_bindings_overlap(self) -> None:
        first = self._new_entry("host-port-one")
        second = self._new_entry("host-port-two")
        common = {
            "target_service": "web",
            "container_port": 3000,
            "host_port": 39001,
            "protocol": "tcp",
            "reason": "Temporary protocol endpoint that cannot use HTTP proxy routing.",
            "approved_by": "platform-security",
            "firewall_scope": "corporate-vpn-only",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        first["published_host_ports"] = [{**common, "bind_address": "0.0.0.0"}]
        second["published_host_ports"] = [{**common, "bind_address": "127.0.0.1"}]
        report = self._check([self.local, first, second])
        self.assertTrue(any("Overlapping published host port" in error for error in report.errors))

    def test_shared_hostname_requires_non_overlapping_paths(self) -> None:
        first = self._new_entry("shared-one")
        second = self._new_entry("shared-two")
        first["routes"][0]["hostname"] = "shared.example.invalid"
        first["routes"][0]["path"] = "/api"
        first["routes"][0]["shared_hostname"] = True
        second["routes"][0]["hostname"] = "shared.example.invalid"
        second["routes"][0]["path"] = "/api/v2"
        second["routes"][0]["shared_hostname"] = True
        report = self._check([self.local, first, second])
        self.assertTrue(any("Shared hostname routes overlap" in error for error in report.errors))

    def test_non_overlapping_shared_hostname_paths_are_allowed(self) -> None:
        first = self._new_entry("shared-alpha")
        second = self._new_entry("shared-beta")
        first["routes"][0]["hostname"] = "shared-safe.example.invalid"
        first["routes"][0]["path"] = "/alpha"
        first["routes"][0]["shared_hostname"] = True
        second["routes"][0]["hostname"] = "shared-safe.example.invalid"
        second["routes"][0]["path"] = "/beta"
        second["routes"][0]["shared_hostname"] = True
        report = self._check([self.local, first, second])
        self.assertEqual([], report.errors, "\n".join(report.errors))

    def test_expired_host_port_exception_is_rejected(self) -> None:
        entry = self._new_entry("expired-port")
        entry["published_host_ports"] = [{
            "target_service": "web",
            "container_port": 3000,
            "host_port": 39002,
            "protocol": "tcp",
            "bind_address": "127.0.0.1",
            "reason": "Temporary protocol endpoint that cannot use HTTP proxy routing.",
            "approved_by": "platform-security",
            "firewall_scope": "localhost-only",
            "expires_at": "2025-01-01T00:00:00Z",
        }]
        report = self._check([self.local, entry])
        self.assertTrue(any("Expired published host-port exception" in error for error in report.errors))

    def test_local_registration_must_match_central_entry(self) -> None:
        changed = copy.deepcopy(self.local)
        changed["coolify"]["resource_name"] = "different-resource"
        report = self._check([changed])
        self.assertTrue(any("differs from deployment.registration.yaml" in error for error in report.errors))


if __name__ == "__main__":
    unittest.main()
