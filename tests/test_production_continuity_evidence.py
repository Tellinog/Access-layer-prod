from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_production_continuity", ROOT / "scripts/validate_production_continuity.py")
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

    def restore_ready_evidence(self, mode: str = "inline_env") -> dict:
        evidence = copy.deepcopy(self.template)
        evidence.update(captured_at="2026-08-25T10:00:00Z", captured_by="synthetic-operator")
        evidence["coolify"].update(
            server_id="server-1", project_id="project-1", environment_id="production",
            resource_id="resource-1", destination_id="destination-1", resource_type="service",
            auto_deploy_enabled=False,
        )
        evidence["domains"].update(
            live_current_origin="https://access-layer.example.test",
            live_current_origin_observed_from="synthetic Coolify record",
        )
        evidence["runtime"].update(
            deployed_revision="a" * 40, image_reference="registry.example.test/access-layer:synthetic",
            image_digest="sha256:" + "b" * 64, replica_count=1,
            deployment_strategy="single replica", last_deployed_at="2026-08-25T09:00:00Z",
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
            actual_storage_type="named_volume", actual_storage_identifier="postgres-volume-synthetic",
            mapping_observed_from="synthetic narrow inspect", mapping_verified=True,
            verified_at="2026-08-25T10:00:00Z", verified_by="synthetic-operator",
            evidence_reference="protected-postgres-mount-record",
        )
        evidence["backup"].update(
            mechanism="synthetic logical backup", schedule="daily", retention="30 days",
            storage_destination_class="off-host synthetic", latest_verified_backup_id="backup-1",
            latest_verified_backup_at="2026-08-25T08:00:00Z",
            evidence_reference="protected-backup-record",
        )
        evidence["database"].update(
            metadata_collected=True, collected_at="2026-08-25T10:00:00Z", server_version="16.4",
            database_name="access_layer_synthetic", schema_fingerprint_sha256="c" * 64,
            applied_migration_ids=["001_initial.sql"], metadata_source="synthetic read-only collector",
        )

        states = evidence["configuration"]["environment_state"]
        for name in states:
            states[name] = "PRESENT_NON_EMPTY"
        states["PUBLIC_BASE_PATH"] = "PRESENT_EMPTY"
        states["SIEM_EXPORT_ENDPOINT"] = "ABSENT"
        states["SIEM_EXPORT_TOKEN"] = "ABSENT"
        states["BACKUP_API_TOKEN"] = "ABSENT"
        if mode == "inline_env":
            states["JWT_PRIVATE_KEY_PEM"] = "PRESENT_NON_EMPTY"
            states["JWT_PRIVATE_KEY_PEM_PATH"] = "PRESENT_EMPTY"
        else:
            states["JWT_PRIVATE_KEY_PEM"] = "PRESENT_EMPTY"
            states["JWT_PRIVATE_KEY_PEM_PATH"] = "PRESENT_NON_EMPTY"

        evidence["configuration"]["observation"].update(
            observed_at="2026-08-25T10:00:00Z", observed_by="synthetic-operator",
            evidence_reference="protected-config-record", runtime_config_validation_observed=True,
        )
        evidence["configuration"]["effective_non_secret_config"].update(
            app_env="production", public_base_path="", app_base_url="https://access-layer.example.test",
            auth_issuer="https://access-layer.example.test", port=8080, log_level="info",
            postgres_user="access_layer", postgres_database="access_layer", google_client_id="public-client-id",
            google_redirect_uri="https://access-layer.example.test/v1/auth/google/callback",
            google_allowed_hd=["example.test"], google_oidc_scope=["openid", "email", "profile"],
            jwt_public_key_id="synthetic-kid", access_token_ttl_seconds=900,
            refresh_token_ttl_seconds=28800, one_time_code_ttl_seconds=60,
            enable_refresh_tokens=True, oauth_p0_enabled=False, session_cookie_name="access_layer_admin_session",
            cors_allowed_origins=["https://access-layer.example.test"], return_url_allowed_schemes=["https"],
            trust_proxy_hops=1, audit_log_retention_days=365, audit_log_raw_ip=False,
            access_request_reopen_after_days=30, run_migrations_on_start=True,
            run_seed_on_start=True, seed_example_tools=False, siem_export_enabled=False,
            siem_export_endpoint=None, admin_bootstrap_email_count=1,
        )
        jwt = evidence["jwt_signing_material"]
        jwt.update(
            source_mode=mode, configured_file_path=None if mode == "inline_env" else "/run/secrets/access-layer-jwt-private.pem",
            file_state="UNOBSERVED" if mode == "inline_env" else "PRESENT_NON_EMPTY",
        )
        jwt["public_key"].update(
            jwks_observed_from="synthetic public JWKS", kid="synthetic-kid", fingerprint_sha256="d" * 64,
        )
        jwt["continuity_verification"].update(
            verified_same_key=True, verification_method="public_key_comparison",
            verified_by="synthetic-operator", verified_at="2026-08-25T10:00:00Z",
            evidence_reference="protected-key-comparison-record",
        )
        if mode == "file_path":
            jwt["file_persistence"].update(
                actual_storage_type="named_volume", actual_storage_identifier="jwt-volume-synthetic",
                mapping_observed_from="synthetic narrow inspect", mapping_verified=True,
                verified_at="2026-08-25T10:00:00Z", verified_by="synthetic-operator",
                evidence_reference="protected-jwt-mount-record",
            )
        for record in evidence["secret_continuity"]["records"].values():
            record.update(
                verified_same_value=True, verification_method="secret_manager_version_reference",
                verified_by="synthetic-operator", verified_at="2026-08-25T10:00:00Z",
                evidence_reference="protected-secret-version-record",
            )
        evidence["deployment_registry"].update(
            record_verified=True, registry_identifier="registry-record-1",
            evidence_reference="protected-registry-record",
        )
        evidence["ownership"].update(
            owner_team="team", technical_owner="technical-owner", product_owner="product-owner",
            continuity_operator="synthetic-operator",
        )
        for key in (
            "live_topology_verified", "postgres_storage_mapping_verified", "backup_policy_verified",
            "jwt_signing_material_verified", "secret_continuity_verified", "configuration_verified",
            "ready_for_isolated_restore",
        ):
            evidence["approvals"][key] = True
        return evidence

    def test_committed_bundle_is_valid_and_both_gates_are_false(self) -> None:
        report = validator.validate(self.path)
        self.assertEqual("VALID_BUT_NOT_READY", report.result)
        self.assertEqual(2, report.exit_code)
        self.assertFalse(report.ready_for_isolated_restore)
        self.assertFalse(report.ready_for_n_to_n_plus_1)
        self.assertIn("jwt_signing_material.source_mode", report.missing_for_isolated_restore)

    def test_committed_bundle_records_proven_coolify_ids_only(self) -> None:
        coolify = self.template["coolify"]
        self.assertEqual("wx513ojqd80kdicevubog7", coolify["server_id"])
        self.assertEqual("xdihnb979tvyh9gdk72zfy7y", coolify["project_id"])
        self.assertEqual("rd3mt4dkpqyghxlx9h96sdlo", coolify["environment_id"])
        self.assertEqual("u3cyw3y1obp88to9la0w8c75", coolify["resource_id"])
        self.assertIsNone(coolify["destination_id"])

    def test_file_backed_key_requires_verified_secret_mount(self) -> None:
        evidence = self.restore_ready_evidence("file_path")
        evidence["jwt_signing_material"]["file_persistence"]["mapping_verified"] = False
        report = self.write_and_validate(evidence)
        self.assertFalse(report.ready_for_isolated_restore)
        self.assertIn("jwt_signing_material.file_persistence.mapping_verified=true", report.missing_for_isolated_restore)

    def test_inline_key_needs_public_proof_but_not_secret_mount(self) -> None:
        evidence = self.restore_ready_evidence("inline_env")
        report = self.write_and_validate(evidence)
        self.assertTrue(report.ready_for_isolated_restore, report.missing_for_isolated_restore)
        self.assertTrue(evidence["jwt_signing_material"]["file_persistence"]["mapping_verified"])
        self.assertNotIn(
            "jwt_signing_material.file_persistence.mapping_verified=true",
            report.missing_for_isolated_restore,
        )
        evidence["jwt_signing_material"]["public_key"]["fingerprint_sha256"] = None
        report = self.write_and_validate(evidence)
        self.assertFalse(report.ready_for_isolated_restore)

    def test_empty_session_secret_is_distinct_and_blocks_restore_gate(self) -> None:
        evidence = self.restore_ready_evidence()
        evidence["configuration"]["environment_state"]["SESSION_SECRET"] = "PRESENT_EMPTY"
        report = self.write_and_validate(evidence)
        self.assertFalse(report.ready_for_isolated_restore)
        self.assertIn("configuration.environment_state.SESSION_SECRET=PRESENT_NON_EMPTY", report.missing_for_isolated_restore)

    def test_empty_public_base_path_is_valid_observed_configuration(self) -> None:
        evidence = self.restore_ready_evidence()
        self.assertEqual("PRESENT_EMPTY", evidence["configuration"]["environment_state"]["PUBLIC_BASE_PATH"])
        self.assertEqual("", evidence["configuration"]["effective_non_secret_config"]["public_base_path"])
        report = self.write_and_validate(evidence)
        self.assertTrue(report.ready_for_isolated_restore, report.missing_for_isolated_restore)

    def test_step_3a_oauth_foundation_flag_must_remain_false_for_restore_gate(self) -> None:
        evidence = self.restore_ready_evidence()
        evidence["configuration"]["effective_non_secret_config"]["oauth_p0_enabled"] = True
        report = self.write_and_validate(evidence)
        self.assertFalse(report.ready_for_isolated_restore)
        self.assertIn(
            "configuration.effective_non_secret_config.oauth_p0_enabled=false",
            report.missing_for_isolated_restore,
        )

    def test_jwt_pem_or_path_alternatives_both_work(self) -> None:
        self.assertTrue(self.write_and_validate(self.restore_ready_evidence("inline_env")).ready_for_isolated_restore)
        self.assertTrue(self.write_and_validate(self.restore_ready_evidence("file_path")).ready_for_isolated_restore)

    def test_secret_sameness_verification_is_required(self) -> None:
        evidence = self.restore_ready_evidence()
        evidence["secret_continuity"]["records"]["TOOL_CLIENT_SECRET_PEPPER"]["verified_same_value"] = False
        report = self.write_and_validate(evidence)
        self.assertFalse(report.ready_for_isolated_restore)
        self.assertIn(
            "secret_continuity.records.TOOL_CLIENT_SECRET_PEPPER.verified_same_value=true",
            report.missing_for_isolated_restore,
        )

    def test_restore_gate_can_pass_while_final_gate_remains_blocked(self) -> None:
        evidence = self.restore_ready_evidence()
        report = self.write_and_validate(evidence)
        self.assertTrue(report.ready_for_isolated_restore, report.missing_for_isolated_restore)
        self.assertFalse(report.ready_for_n_to_n_plus_1)
        self.assertIn("backup.restore_test.status=PASSED", report.missing_for_n_to_n_plus_1)

    def test_full_synthetic_bundle_can_be_final_ready_only_after_restore(self) -> None:
        evidence = self.restore_ready_evidence("file_path")
        evidence["backup"]["restore_test"].update(
            status="PASSED", isolated_target=True, target_identifier="isolated-db",
            completed_at="2026-08-25T11:00:00Z", verified_by="synthetic-operator",
            evidence_reference="protected-restore-record",
        )
        evidence["approvals"]["restore_test_verified"] = True
        evidence["approvals"]["ready_for_n_to_n_plus_1"] = True
        evidence["status"] = "READY"
        report = self.write_and_validate(evidence)
        self.assertEqual("READY", report.result, report.errors + report.missing_readiness_facts)
        self.assertTrue(report.ready_for_isolated_restore)
        self.assertTrue(report.ready_for_n_to_n_plus_1)

    def test_false_ready_claim_and_reusable_secret_verifier_are_rejected(self) -> None:
        evidence = copy.deepcopy(self.template)
        evidence["status"] = "READY"
        report = self.write_and_validate(evidence)
        self.assertEqual("INVALID", report.result)
        evidence = copy.deepcopy(self.template)
        evidence["secret_continuity"]["records"]["SESSION_SECRET"]["evidence_reference"] = "e" * 64
        report = self.write_and_validate(evidence)
        self.assertEqual("INVALID", report.result)
        self.assertTrue(any("reusable secret verifier" in error for error in report.errors))
        self.assertNotIn("e" * 64, repr(report))

    def test_connection_credentials_are_rejected_without_echoing_value(self) -> None:
        evidence = copy.deepcopy(self.template)
        sentinel = "postgresql://continuity-user:continuity-password@example.test/database"
        evidence["database"]["metadata_source"] = sentinel
        report = self.write_and_validate(evidence)
        self.assertEqual("INVALID", report.result)
        self.assertNotIn(sentinel, repr(report))


if __name__ == "__main__":
    unittest.main()
