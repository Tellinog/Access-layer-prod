from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


class ExampleSchemaTests(unittest.TestCase):
    def assert_valid(self, example: str, schema: str) -> None:
        instance = json.loads((ROOT / example).read_text(encoding="utf-8"))
        definition = json.loads((ROOT / schema).read_text(encoding="utf-8"))
        failures = list(Draft202012Validator(definition, format_checker=FormatChecker()).iter_errors(instance))
        self.assertEqual([], [failure.message for failure in failures])

    def test_request_context_examples(self) -> None:
        self.assert_valid("examples/auth/request-context.legacy.json", "schemas/request-context.schema.json")
        self.assert_valid("examples/auth/request-context.oauth.json", "schemas/request-context.schema.json")

    def test_mcp_resource_metadata(self) -> None:
        self.assert_valid("examples/oauth/oauth-protected-resource-metadata.json", "schemas/oauth-protected-resource-metadata.schema.json")

    def test_ai_output_envelope(self) -> None:
        self.assert_valid("examples/ai/ai-output-envelope.json", "schemas/ai-output-envelope.schema.json")

    def test_product_event(self) -> None:
        self.assert_valid("examples/telemetry/capability-completed.event.json", "schemas/events.schema.json")

    def assert_valid_yaml(self, example: str, schema: str) -> None:
        instance = yaml.safe_load((ROOT / example).read_text(encoding="utf-8"))
        definition = json.loads((ROOT / schema).read_text(encoding="utf-8"))
        failures = list(Draft202012Validator(definition, format_checker=FormatChecker()).iter_errors(instance))
        self.assertEqual([], [failure.message for failure in failures])

    def test_deployment_registration(self) -> None:
        self.assert_valid_yaml("deployment.registration.yaml", "schemas/deployment-registration.schema.json")

    def test_example_deployment_registry(self) -> None:
        self.assert_valid_yaml("examples/registry/deployments.yml", "schemas/deployment-registry.schema.json")

    def test_full_project_manifest_examples(self) -> None:
        self.assert_valid_yaml("examples/manifests/greenfield.project.platform.yaml", "schemas/project-platform.schema.json")
        self.assert_valid_yaml("examples/manifests/legacy-migration.project.platform.yaml", "schemas/project-platform.schema.json")


if __name__ == "__main__":
    unittest.main()
