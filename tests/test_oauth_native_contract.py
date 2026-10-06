"""Validate the separate post-P0 native entitlement machine contract."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SPEC = yaml.safe_load((ROOT / "specs/oauth-native-entitlements.v1.yml").read_text(encoding="utf-8"))
ADMIN_SPEC = yaml.safe_load((ROOT / "specs/oauth-admin-operability.v1.yml").read_text(encoding="utf-8"))
ADMIN_API = yaml.safe_load((ROOT / "schemas/access-layer-oauth-admin-p0.openapi.yaml").read_text(encoding="utf-8"))
GRANT_SCHEMA = json.loads((ROOT / "schemas/oauth-native-human-grant.schema.json").read_text(encoding="utf-8"))
PROVENANCE_SCHEMA = json.loads((ROOT / "schemas/oauth-authorization-native-grant.schema.json").read_text(encoding="utf-8"))
UUID = "00000000-0000-4000-8000-000000000001"
OTHER_UUID = "00000000-0000-4000-8000-000000000002"
NOW = "2026-09-28T11:00:00Z"


class NativeOAuthContractTest(unittest.TestCase):
    def test_bulk_admin_contract_is_bounded_and_keeps_stable_principals(self) -> None:
        self.assertEqual(ADMIN_SPEC["phase"], "9A.4")
        self.assertEqual(ADMIN_SPEC["database_migration"], "none")
        self.assertEqual(ADMIN_SPEC["scope_catalogue"]["max_rows"], 200)
        self.assertEqual(ADMIN_SPEC["scope_catalogue"]["comma_delimiter"], "forbidden")
        self.assertEqual(ADMIN_SPEC["native_grants"]["principal"], "users.id")
        self.assertEqual(ADMIN_SPEC["native_grants"]["max_matrix"], 1000)
        self.assertEqual(ADMIN_SPEC["native_grants"]["pending_email_writer"], "unknown_email_with_approved_domain")
        self.assertEqual(ADMIN_SPEC["audit_failure"], "rollback")
        self.assertEqual(ADMIN_SPEC["single_entity_by_design"],
                         ["resource_creation", "client_creation", "credential_rotation", "signing_key_lifecycle"])

    def test_bulk_scope_schema_accepts_structured_rows_and_bounds_the_batch(self) -> None:
        schema = ADMIN_API["components"]["schemas"]["ScopeBulk"]
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        row = {"scope": "synthetic:records:read", "description": "Read records, including drafts; safely"}
        self.assertTrue(validator.is_valid({"rows": [row]}))
        self.assertTrue(validator.is_valid({"rows": [row] * 200}))
        self.assertFalse(validator.is_valid({"rows": [row] * 201}))
        self.assertFalse(validator.is_valid({"rows": "scope ; description"}))
        for kind in ("AllowanceReplacementCommit", "RedirectReplacementCommit"):
            self.assertIn("expected_current", ADMIN_API["components"]["schemas"][kind]["required"])

    def test_machine_contract_preserves_p0_and_direct_mode_guard(self) -> None:
        self.assertEqual(SPEC["phase"], "9A.3")
        self.assertEqual(SPEC["p0_profile"], "frozen_legacy_bridge_compatibility")
        self.assertEqual(SPEC["runtime_evaluation"], "mode_selected_exact_current_entitlement")
        self.assertEqual(SPEC["resource_entitlement_modes"], ["legacy_bridge", "native"])
        self.assertEqual(SPEC["resource_mode_phase_9A_1"], "direct_update_forbidden")
        self.assertTrue(SPEC["resource_mode_target_transition"]["same_resource_id_and_audience"] == "required")
        self.assertTrue(SPEC["authorization_provenance"]["source_must_match_resource_mode_at_insert"])
        self.assertFalse(SPEC["authorization_provenance"]["historical_links_replace_current_entitlement_evaluation"])
        self.assertEqual(SPEC["native"]["linked_principal"], "users.id")
        self.assertFalse(SPEC["native"]["pending_email_runtime_effective"])
        self.assertEqual(SPEC["native"]["legacy_fallback"], "forbidden")
        self.assertTrue(SPEC["authorization_provenance"]["lifecycle_source_must_match_current_resource_mode"])
        self.assertEqual(SPEC["backup"]["native_authorization_writer"], "implemented")
        self.assertEqual(SPEC["backup"]["native_admin_grant_writer"], "implemented_for_existing_linked_users_and_bulk_pending_email")
        self.assertEqual(SPEC["admin"]["permission_write"], "admin:oauth:write")
        self.assertEqual(SPEC["admin"]["pending_email_writer"], "bulk_only_approved_domains")
        self.assertEqual(SPEC["native"]["pending_email_link"], "automatic_at_verified_login_any_approved_provider_same_transaction")

    def test_schemas_compile_and_validate_native_rows(self) -> None:
        for schema in (GRANT_SCHEMA, PROVENANCE_SCHEMA):
            Draft202012Validator.check_schema(schema)
        grant = {
            "id": UUID,
            "oauth_resource_id": UUID,
            "oauth_scope_id": UUID,
            "user_id": OTHER_UUID,
            "email_normalized": None,
            "status": "active",
            "valid_from": NOW,
            "valid_until": None,
            "created_by_user_id": None,
            "revoked_by_user_id": None,
            "revoked_at": None,
            "created_at": NOW,
            "updated_at": NOW,
        }
        validator = Draft202012Validator(GRANT_SCHEMA, format_checker=FormatChecker())
        self.assertTrue(validator.is_valid(grant))
        self.assertFalse(validator.is_valid({**grant, "status": "pending_user_link"}))
        self.assertFalse(validator.is_valid({**grant, "status": "revoked"}))
        provenance = {
            "id": UUID,
            "oauth_authorization_id": UUID,
            "oauth_native_human_grant_id": OTHER_UUID,
            "created_at": NOW,
        }
        self.assertTrue(Draft202012Validator(PROVENANCE_SCHEMA, format_checker=FormatChecker()).is_valid(provenance))


if __name__ == "__main__":
    unittest.main()
