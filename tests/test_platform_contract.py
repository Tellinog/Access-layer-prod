from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


class PlatformContractTests(unittest.TestCase):
    def test_static_platform_check_passes_for_template(self) -> None:
        manifest = yaml.safe_load((ROOT / "project.platform.yaml").read_text())
        command = [
            sys.executable,
            str(ROOT / "scripts/platform_check.py"),
            "--root",
            str(ROOT),
            "--json",
        ]
        # The pristine template is allowed to contain explicit project-input
        # markers. A bootstrapped repository runs the non-strict contract test
        # until those release gates are deliberately resolved.
        if manifest.get("template_mode"):
            command.insert(-1, "--strict")
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["summary"]["errors"], 0)

    def test_manifest_capability_mapping_is_one_to_one(self) -> None:
        manifest = yaml.safe_load((ROOT / "project.platform.yaml").read_text())
        for capability in manifest["capabilities"]:
            capability_id = capability["capability_id"]
            self.assertEqual(capability["permission"], capability_id)
            self.assertEqual(capability["oauth_scope"], capability_id)
            self.assertRegex(capability_id, r"^[a-z][a-z0-9-]+(?::[a-z][a-z0-9-]+){1,}$")

    def test_legacy_migration_preserves_legacy_invariants(self) -> None:
        manifest = yaml.safe_load((ROOT / "project.platform.yaml").read_text())
        self.assertEqual(manifest["authentication"]["compatibility_mode"], "legacy-only")
        legacy = manifest["authentication"]["legacy"]
        self.assertTrue(legacy["enabled"])
        self.assertFalse(legacy["forced_migration"])
        for key in (
            "preserve_existing_consumers",
            "preserve_active_sessions",
            "preserve_refresh_tokens",
            "preserve_token_claims",
            "preserve_endpoints_and_payloads",
            "rollback_without_data_loss",
        ):
            self.assertTrue(legacy[key], key)

    def test_coolify_deployment_contract_is_explicit(self) -> None:
        manifest = yaml.safe_load((ROOT / "project.platform.yaml").read_text())
        deployment = manifest["deployment"]
        self.assertEqual("platform_service", manifest["project"]["kind"])
        self.assertEqual("legacy-migration", manifest["project"]["mode"])
        self.assertEqual("coolify", deployment["platform"])
        self.assertEqual("one-coolify-resource-per-project", deployment["unit_policy"])
        self.assertTrue(deployment["port_policy"]["container_ports_may_repeat_across_coolify_resources"])
        self.assertTrue(deployment["port_policy"]["host_ports_forbidden_by_default"])
        self.assertEqual([], deployment["port_policy"]["published_host_ports"])
        route = deployment["public_routes"][0]
        service = deployment["services"][0]
        self.assertEqual(route["target_service"], service["service_name"])
        self.assertEqual(route["target_container_port"], service["container_port"])
        self.assertEqual("0.0.0.0", service["bind_address"])

    def test_telemetry_component_boundaries_are_named(self) -> None:
        manifest = yaml.safe_load((ROOT / "project.platform.yaml").read_text())
        telemetry = manifest["telemetry"]
        self.assertEqual("unguess-platform-sdk", telemetry["instrumentation_source"])
        self.assertEqual("unguess-observability-stack", telemetry["technical_destination"])
        self.assertEqual("tool-observatory", telemetry["product_event_destination"])


class ExampleSchemaTests(unittest.TestCase):
    def validate(self, instance_rel: str, schema_rel: str) -> None:
        instance = json.loads((ROOT / instance_rel).read_text())
        schema = json.loads((ROOT / schema_rel).read_text())
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance),
            key=lambda error: list(error.absolute_path),
        )
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

    def test_legacy_exchange_example(self) -> None:
        self.validate(
            "examples/access-layer/legacy-exchange.response.json",
            "schemas/legacy-access-layer-exchange.schema.json",
        )

    def test_legacy_introspection_examples(self) -> None:
        self.validate(
            "examples/access-layer/legacy-introspection.active.json",
            "schemas/legacy-access-layer-introspection.schema.json",
        )
        self.validate(
            "examples/access-layer/legacy-introspection.inactive.json",
            "schemas/legacy-access-layer-introspection.schema.json",
        )

    def test_oauth_claims_example(self) -> None:
        self.validate(
            "examples/oauth/access-token.claims.json",
            "schemas/oauth-access-token-claims.schema.json",
        )

    def test_product_event_example(self) -> None:
        self.validate(
            "examples/telemetry/capability-completed.event.json",
            "schemas/events.schema.json",
        )

    def test_ai_examples(self) -> None:
        self.validate(
            "examples/ai/ai-output-envelope.json",
            "schemas/ai-output-envelope.schema.json",
        )
        self.validate(
            "examples/ai/ai-output-approved.event.json",
            "schemas/ai-events.schema.json",
        )


if __name__ == "__main__":
    unittest.main()
