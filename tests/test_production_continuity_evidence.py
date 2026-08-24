from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_production_continuity",
    ROOT / "scripts" / "validate_production_continuity.py",
)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


class ProductionContinuityEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = ROOT / "operations" / "production-continuity.evidence.yml"
        self.template = yaml.safe_load(self.path.read_text(encoding="utf-8"))

    def write_and_validate(self, evidence: dict) -> object:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.yml"
            path.write_text(yaml.safe_dump(evidence, sort_keys=False), encoding="utf-8")
            return validator.validate(path)

    def test_committed_bundle_is_valid_but_not_ready(self) -> None:
        report = validator.validate(self.path)
        self.assertEqual("VALID_BUT_NOT_READY", report.result)
        self.assertEqual(2, report.exit_code)
        self.assertIn("storage.actual_storage_identifier", report.missing_readiness_facts)
        self.assertIn("ownership.technical_owner", report.missing_readiness_facts)
        self.assertIn("backup.restore_test.status=PASSED", report.missing_readiness_facts)

    def test_ready_claim_is_rejected_when_evidence_is_missing(self) -> None:
        evidence = copy.deepcopy(self.template)
        evidence["status"] = "READY"
        report = self.write_and_validate(evidence)
        self.assertEqual("INVALID", report.result)
        self.assertTrue(report.missing_readiness_facts)

    def test_secret_bearing_extension_is_rejected_without_echoing_value(self) -> None:
        evidence = copy.deepcopy(self.template)
        sentinel = "do-not-echo-this-password"
        evidence["database"]["password"] = sentinel
        report = self.write_and_validate(evidence)
        self.assertEqual("INVALID", report.result)
        self.assertTrue(any("forbidden secret-bearing field" in item for item in report.errors))
        self.assertNotIn(sentinel, repr(report))

    def test_connection_credentials_are_rejected_without_echoing_value(self) -> None:
        evidence = copy.deepcopy(self.template)
        sentinel = "postgresql://continuity-user:continuity-password@example.test/database"
        evidence["database"]["metadata_source"] = sentinel
        report = self.write_and_validate(evidence)
        self.assertEqual("INVALID", report.result)
        self.assertTrue(any("secret value" in item or "URL credentials" in item for item in report.errors))
        self.assertNotIn(sentinel, repr(report))

    def test_full_synthetic_bundle_can_be_ready(self) -> None:
        evidence = copy.deepcopy(self.template)
        evidence.update(status="READY", captured_at="2026-08-24T12:00:00Z", captured_by="synthetic-test-operator")
        evidence["coolify"].update(
            server_id="server-1", project_id="project-1", environment_id="production",
            resource_id="resource-1", destination_id="destination-1",
            resource_type="service", auto_deploy_enabled=False,
        )
        evidence["domains"].update(
            live_current_origin="https://access-layer.example.test",
            live_current_origin_observed_from="synthetic Coolify UI record",
        )
        evidence["runtime"].update(
            deployed_revision="a" * 40, image_reference="registry.example.test/access-layer:synthetic",
            image_digest="sha256:" + "b" * 64, replica_count=1,
            deployment_strategy="single replica", last_deployed_at="2026-08-24T11:00:00Z",
        )
        evidence["runtime"]["observed_services"]["app"].update(
            service_name="app", target_container_port=8080, public_host_port=None,
            public_host_port_mapping_observed=True, exposure="public_via_proxy",
        )
        evidence["runtime"]["observed_services"]["postgres"].update(
            service_name="postgres", target_container_port=5432, public_host_port=None,
            public_host_port_mapping_observed=True, exposure="private",
        )
        evidence["storage"].update(
            actual_storage_type="named_volume", actual_storage_identifier="volume-synthetic",
            mapping_observed_from="synthetic inspect", mapping_verified=True,
            verified_at="2026-08-24T12:00:00Z", verified_by="synthetic-test-operator",
        )
        evidence["backup"].update(
            mechanism="synthetic logical backup", schedule="daily", retention="30 days",
            storage_destination_class="synthetic off-host", latest_verified_backup_id="backup-1",
            latest_verified_backup_at="2026-08-24T10:00:00Z",
        )
        evidence["backup"]["restore_test"].update(
            status="PASSED", isolated_target=True, target_identifier="isolated-test-db",
            completed_at="2026-08-24T10:30:00Z", verified_by="synthetic-test-operator",
            evidence_reference="synthetic-test-record",
        )
        evidence["database"].update(
            metadata_collected=True, collected_at="2026-08-24T12:00:00Z",
            server_version="16.4", database_name="access_layer_synthetic",
            schema_fingerprint_sha256="c" * 64, applied_migration_ids=["001_initial.sql"],
            metadata_source="synthetic read-only collector",
        )
        evidence["application_continuity"].update(
            jwks_observed_from="synthetic public JWKS", jwt_public_kid="synthetic-kid",
            jwt_public_key_fingerprint_sha256="d" * 64, environment_presence_verified=True,
        )
        for key in evidence["application_continuity"]["required_environment_presence"]:
            evidence["application_continuity"]["required_environment_presence"][key] = True
        evidence["application_continuity"]["required_environment_presence"]["SIEM_EXPORT_TOKEN"] = False
        evidence["deployment_registry"].update(
            record_verified=True, registry_identifier="registry-record-1",
            evidence_reference="synthetic registry export",
        )
        evidence["ownership"].update(
            owner_team="team", technical_owner="technical-owner", product_owner="product-owner",
            continuity_operator="synthetic-test-operator",
        )
        for key in evidence["approvals"]:
            evidence["approvals"][key] = True
        report = self.write_and_validate(evidence)
        self.assertEqual("READY", report.result, report.errors + report.missing_readiness_facts)
        self.assertEqual(0, report.exit_code)


if __name__ == "__main__":
    unittest.main()
