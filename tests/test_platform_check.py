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


class PlatformCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = yaml.safe_load((ROOT / "project.platform.yaml").read_text(encoding="utf-8"))

    def test_template_passes_non_strict_checks(self) -> None:
        report = platform_check.run_checks(ROOT, strict=False)
        self.assertEqual([], report.errors, "\n".join(report.errors))

    def test_strict_check_with_local_registry_exposes_only_known_release_gates(self) -> None:
        local = yaml.safe_load((ROOT / "deployment.registration.yaml").read_text(encoding="utf-8"))
        registry = {
            "schema_version": 1,
            "registry_name": "unguess-coolify-deployments",
            "updated_at": "2026-08-18T12:00:00Z",
            "deployments": [local],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deployments.yml"
            path.write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
            report = platform_check.run_checks(ROOT, strict=True, registry_path=path)
        expected_fragments = (
            "configuration_status is not ready",
            "backup schedule",
            "must be registered in the central deployment registry",
            "Named project ownership is unresolved",
        )
        self.assertEqual(4, len(report.errors), "\n".join(report.errors))
        for fragment in expected_fragments:
            self.assertTrue(any(fragment in error for error in report.errors), fragment)
        self.assertFalse(any("Central deployment registry was not supplied" in warning for warning in report.warnings))

    def test_forced_legacy_migration_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["authentication"]["legacy"]["forced_migration"] = True
        report = platform_check.CheckResult()
        platform_check.check_legacy_compatibility(ROOT, manifest, report)
        self.assertTrue(any("forced_migration" in error for error in report.errors))

    def test_wrong_audience_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["authentication"]["oauth"]["audience"] = "https://another-resource.invalid"
        report = platform_check.CheckResult()
        platform_check.check_capability_contract(ROOT, manifest, report)
        self.assertTrue(any("audience" in error.lower() for error in report.errors))

    def test_resolved_legacy_volumes_do_not_create_a_continuity_error(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["template_mode"] = True
        report = platform_check.CheckResult()
        platform_check.check_security_and_placeholders(ROOT, manifest, report, strict=True)
        self.assertEqual([], report.errors)
        self.assertTrue(report.warnings)


if __name__ == "__main__":
    unittest.main()
